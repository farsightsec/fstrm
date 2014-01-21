/*
 * Copyright (c) 2013-2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * It's not that the items are going into the queue twice. And when I come, I
 * will remember my covenant with you.
 *
 *      -- King James Programming
 */

#include "fstrm-private.h"

static void *fs_io_thr(void *);

struct fs_queue_entry {
	/* The actual payload's bytes, allocated by the caller. */
	void				*bytes;

	/* Length of 'bytes', in big-endian byte order. */
	uint32_t			be32_len;

	/* The deallocation callback. */
	void				(*free_func)(void *, void *);
	void				*free_data;
};

struct fstrm_queue {
	struct my_queue			*q;
};

struct fstrm_io {
	/* Deep copy of options supplied by caller. */
	struct fstrm_io_options		opt;

	/* Queue implementation. */
	const struct my_queue_ops	*queue_ops;

	/* Data returned by call to writer's 'create' method. */
	void				*writer_data;

	/* The last time the writer's 'connect' method was called. */
	time_t				last_connect_attempt;

	/* Allocated array of queues, size opt.num_queues. */
	struct fstrm_queue		*queues;

	/* The I/O thread. */
	pthread_t			thr;

	/* Whether the writer is writable or not. */
	bool				writable;

	/* Whether the I/O thread is shutting down. */
	volatile bool			shutting_down;

	/* Optimal clockid_t's. */
	clockid_t			clkid_gettime;
	clockid_t			clkid_pthread;

	/*
	 * Conditional variable and lock, used by producer thread
	 * (fstrm_io_submit) to signal sleeping I/O thread that the low
	 * water-mark (opt.queue_notify_threshold) has been reached.
	 */
	pthread_cond_t			cv;
	pthread_mutex_t			cv_lock;

	/* Used to return unique queues from fstrm_io_get_queue(). */
	unsigned			get_queue_idx;
	pthread_mutex_t			get_queue_lock;

	/* Outstanding wire data. */
	struct iovec			*iov_array;
	unsigned			iov_bytes;
	unsigned			iov_idx;

	/* Outstanding queue entries. */
	struct fs_queue_entry		*qe_array;
	unsigned			qe_idx;
};

struct fstrm_io *
fstrm_io_init(const struct fstrm_io_options *opt, char **err)
{
	struct fstrm_io *io = NULL;

	int res;
	pthread_condattr_t ca;

	/* Initialize fstrm_io and copy options. */
	io = my_calloc(1, sizeof(*io));
	fs_io_options_dup(&io->opt, opt);

	/*
	 * Some platforms have a ridiculously low IOV_MAX, literally the lowest
	 * value even allowed by POSIX, which is lower than our conservative
	 * FSTRM_DEFAULT_IO_IOVEC_SIZE. Accomodate these platforms by silently
	 * clamping io->opt.iovec_size to IOV_MAX.
	 */
	if (io->opt.iovec_size > IOV_MAX)
		io->opt.iovec_size = IOV_MAX;

	/*
	 * Set the queue implementation.
	 *
	 * The memory barrier based queue implementation is the only one of our
	 * queue implementations that supports SPSC, so if it is not available,
	 * use the mutex based queue implementation instead. The mutex
	 * implementation is technically MPSC, but MPSC is strictly stronger
	 * than SPSC.
	 */
	if (io->opt.queue_model == FSTRM_QUEUE_MODEL_SPSC) {
#ifdef MY_HAVE_MEMORY_BARRIERS
		io->queue_ops = &my_queue_mb_ops;
#else
		io->queue_ops = &my_queue_mutex_ops;
#endif
	} else {
		io->queue_ops = &my_queue_mutex_ops;
	}

	/* Validate options. */
	if (!fs_io_options_validate(&io->opt, err))
		goto err_out;

	/* Detect best clocks. */
	if (!fs_get_best_monotonic_clocks(&io->clkid_gettime,
					  &io->clkid_pthread,
					  err))
	{
		goto err_out;
	}

	/* Initialize the queues. */
	io->queues = my_calloc(io->opt.num_queues, sizeof(struct fstrm_queue));
	for (size_t i = 0; i < io->opt.num_queues; i++) {
		io->queues[i].q = io->queue_ops->init(io->opt.queue_length,
						      sizeof(struct fs_queue_entry));
		if (io->queues[i].q == NULL) {
			if (err != NULL)
				*err = my_strdup("io->queue_ops->init() failed");
			goto err_out;
		}
	}

	/* Initialize the arrays. */
	io->iov_array = my_calloc(io->opt.iovec_size, sizeof(struct iovec));
	io->qe_array = my_calloc(io->opt.iovec_size / 2, sizeof(struct fs_queue_entry));

	/* Initialize the condition variable. */
	res = pthread_condattr_init(&ca);
	assert(res == 0);

	res = pthread_condattr_setclock(&ca, io->clkid_pthread);
	assert(res == 0);

	res = pthread_cond_init(&io->cv, &ca);
	assert(res == 0);

	res = pthread_condattr_destroy(&ca);
	assert(res == 0);

	/* Initialize the mutex protecting the condition variable. */
	res = pthread_mutex_init(&io->cv_lock, NULL);
	assert(res == 0);

	/* Initialize the mutex protecting fstrm_io_get_queue(). */
	res = pthread_mutex_init(&io->get_queue_lock, NULL);
	assert(res == 0);

	/*
	 * Initialize the writer by calling its 'create' method. This is done
	 * only once, here in fstrm_io_init(). The corresponding 'destroy'
	 * method will be called in fstrm_io_destroy().
	 */
	res = io->opt.writer->create(io, io->opt.writer_options, &io->writer_data);
	if (res != FSTRM_RES_SUCCESS) {
		if (err != NULL)
			*err = my_strdup("writer 'create' method failed");
		goto err_out;
	}

	/*
	 * Erase the reference to the caller's fstrm_writer_options. The caller
	 * must be able to destroy the writer-options object once fstrm_io_init()
	 * returns.
	 */
	io->opt.writer_options = NULL;

	/* Start the I/O thread. */
	res = pthread_create(&io->thr, NULL, fs_io_thr, io);
	assert(res == 0);

	return io;

err_out:
	fstrm_io_destroy(&io);
	return NULL;
}

static void
fs_entry_free_bytes(struct fs_queue_entry *entry)
{
	if (entry->free_func != NULL)
		entry->free_func(entry->bytes, entry->free_data);
}

static void
fs_io_free_queues(struct fstrm_io *io)
{
	size_t i;
	for (i = 0; i < io->opt.num_queues; i++) {
		struct my_queue *queue;
		struct fs_queue_entry entry;

		queue = io->queues[i].q;
		while (io->queue_ops->remove(queue, &entry, NULL))
			fs_entry_free_bytes(&entry);
		io->queue_ops->destroy(&queue);
	}
	free(io->queues);
}

void
fstrm_io_destroy(struct fstrm_io **io)
{
	if (*io != NULL) {
		/*
		 * Signal the I/O thread that a shutdown is in progress.
		 * This waits for the I/O thread to finish.
		 */
		(*io)->shutting_down = true;
		pthread_cond_signal(&(*io)->cv);
		pthread_join((*io)->thr, NULL);

		/* Destroy the writer by calling its 'destroy' method. */
		if ((*io)->opt.writer->destroy != NULL)
			(*io)->opt.writer->destroy((*io)->writer_data);

		/* Cleanup our allocations. */
		fs_io_free_queues(*io);
		free((*io)->opt.content_type);
		free((*io)->opt.writer);
		free((*io)->iov_array);
		free((*io)->qe_array);
		free(*io);
		*io = NULL;
	}
}

struct fstrm_queue *
fstrm_io_get_queue(struct fstrm_io *io)
{
	struct fstrm_queue *q = NULL;

	pthread_mutex_lock(&io->get_queue_lock);
	if (io->get_queue_idx < io->opt.num_queues) {
		q = &io->queues[io->get_queue_idx];
		io->get_queue_idx++;
	}
	pthread_mutex_unlock(&io->get_queue_lock);

	return q;
}

void
fstrm_free_wrapper(void *ptr,
		   void *data __attribute__((__unused__)))
{
	free(ptr);
}

fstrm_res
fstrm_io_submit(struct fstrm_io *io, struct fstrm_queue *q,
		void *buf, size_t len,
		void (*free_func)(void *, void *), void *free_data)
{
	unsigned space = 0;
	struct fs_queue_entry entry;

	if (unlikely(io->shutting_down))
		return FSTRM_RES_FAILURE;

	if (unlikely(len < 1 || len >= UINT32_MAX || buf == NULL))
		return FSTRM_RES_INVALID;

	entry.bytes = buf;
	entry.be32_len = htonl((uint32_t) len);
	entry.free_func = free_func;
	entry.free_data = free_data;

	if (likely(len > 0) && io->queue_ops->insert(q->q, &entry, &space)) {
		if (space == io->opt.queue_notify_threshold)
			pthread_cond_signal(&io->cv);
		return FSTRM_RES_SUCCESS;
	} else {
		return FSTRM_RES_AGAIN;
	}
}

static void
fs_io_thr_setup(void)
{
	sigset_t set;
	int s;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	s = pthread_sigmask(SIG_BLOCK, &set, NULL);
	assert(s == 0);
}

static fstrm_res
fs_io_open(struct fstrm_io *io)
{
	fstrm_res res;
	res = io->opt.writer->open(io->writer_data);
	if (res == FSTRM_RES_SUCCESS)
		io->writable = true;
	else
		io->writable = false;
	return res;
}

static fstrm_res
fs_io_close(struct fstrm_io *io)
{
	io->writable = false;
	return io->opt.writer->close(io->writer_data);
}

static fstrm_res
fs_io_write_data(struct fstrm_io *io,
		 struct iovec *iov, int iovcnt,
		 unsigned total_length)
{
	fstrm_res res;

	/*
	 * Invoke the writer's 'write_data' method call.
	 * If this fails we need to clean up by invoking the 'close' method call
	 * and marking the writer non-writable.
	 */
	res = io->opt.writer->write_data(io->writer_data,
					 iov, iovcnt,
					 total_length);
	if (res != FSTRM_RES_SUCCESS)
		(void)fs_io_close(io);
	return res;
}

static fstrm_res
fs_io_write_control(struct fstrm_io *io,
		    struct iovec *iov, int iovcnt,
		    unsigned total_length)
{
	fstrm_res res;

	/*
	 * Invoke the writer's 'write_control' method call.
	 * If this fails we need to clean up by invoking the 'close' method call
	 * and marking the writer non-writable.
	 */
	res = io->opt.writer->write_control(io->writer_data,
					    iov, iovcnt,
					    total_length);
	if (res != FSTRM_RES_SUCCESS)
		(void)fs_io_close(io);
	return res;
}

static fstrm_res
fs_io_write_control_start(struct fstrm_io *io)
{
	size_t total_length = 0;

	/*
	 * Calculate the total amount of space needed for the control frame.
	 */

	/* Escape: 32-bit BE integer. Zero. */
	total_length += sizeof(uint32_t);

	/* Frame length: 32-bit BE integer. */
	total_length += sizeof(uint32_t);

	/* Control type: 32-bit BE integer. */
	total_length += sizeof(uint32_t);

	if (io->opt.content_type != NULL) {
		/* FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer. */
		total_length += sizeof(uint32_t);

		/* Length of content type string: 32-bit BE integer. */
		total_length += sizeof(uint32_t);

		/* The content type string itself: 'len_content_type' bytes. */
		total_length += io->opt.len_content_type;
	}

	/* Allocate the storage for the control frame. */
	uint8_t buf[total_length];
	uint32_t tmp;

	/*
	 * Now actually serialize the control frame.
	 */

	/* Escape: 32-bit BE integer. Zero. */
	memset(&buf[0*sizeof(uint32_t)], 0, sizeof(uint32_t));

	/*
	 * Frame length: 32-bit BE integer.
	 *
	 * This does not include the length of the escape frame or the length of
	 * the frame length field itself, so subtract 2*4 bytes from the total
	 * length.
	 */
	tmp = htonl((uint32_t) (total_length - 2*sizeof(uint32_t)));
	memmove(&buf[1*sizeof(uint32_t)], &tmp, sizeof(tmp));

	/* Control type: 32-bit BE integer. */
	tmp = htonl(FSTRM_CONTROL_START);
	memmove(&buf[2*sizeof(uint32_t)], &tmp, sizeof(tmp));

	if (io->opt.content_type != NULL) {
		/* FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer. */
		tmp = htonl(FSTRM_CONTROL_FIELD_CONTENT_TYPE);
		memmove(&buf[3*sizeof(uint32_t)], &tmp, sizeof(tmp));

		/* Length of content type string: 32-bit BE integer. */
		tmp = htonl((uint32_t) io->opt.len_content_type);
		memmove(&buf[4*sizeof(uint32_t)], &tmp, sizeof(tmp));

		/* The content type string itself. */
		memmove(&buf[5*sizeof(uint32_t)], io->opt.content_type, io->opt.len_content_type);
	}

	/* Write the control frame. */
	struct iovec control_iov = {
		.iov_base = (void *) &buf[0],
		.iov_len = total_length,
	};
	return fs_io_write_control(io, &control_iov, 1, (unsigned) total_length);
}

static fstrm_res
fs_io_write_control_stop(struct fstrm_io *io)
{
	size_t total_length = 3*sizeof(uint32_t);
	uint8_t buf[total_length];
	uint32_t tmp;

	/* Escape: 32-bit BE integer. Zero. */
	memset(&buf[0*sizeof(uint32_t)], 0, sizeof(uint32_t));

	/* Frame length: 32-bit BE integer. */
	tmp = htonl((uint32_t) (total_length - 2*sizeof(uint32_t)));
	memmove(&buf[1*sizeof(uint32_t)], &tmp, sizeof(tmp));

	/* Control type: 32-bit BE integer. */
	tmp = htonl(FSTRM_CONTROL_STOP);
	memmove(&buf[2*sizeof(uint32_t)], &tmp, sizeof(tmp));

	/* Write the control frame. */
	struct iovec control_iov = {
		.iov_base = (void *) &buf[0],
		.iov_len = total_length,
	};
	return fs_io_write_control(io, &control_iov, 1, (unsigned) total_length);
}

static void
fs_io_maybe_connect(struct fstrm_io *io)
{
	if (unlikely(!io->writable)) {
		int res;
		time_t since;
		struct timespec ts;

		/*
		 * If we're disconnected and the reconnect interval has expired,
		 * try to reopen the transport.
		 */
		res = clock_gettime(io->clkid_gettime, &ts);
		assert(res == 0);
		since = ts.tv_sec - io->last_connect_attempt;
		if (since >= (time_t) io->opt.reconnect_interval) {
			/* The reconnect interval expired. */

			if (fs_io_open(io) == FSTRM_RES_SUCCESS) {
				/*
				 * The transport has been reopened, so send the
				 * start frame.
				 */
				if (fs_io_write_control_start(io) != FSTRM_RES_SUCCESS) {
					/*
					 * Writing the control frame failed, so
					 * close the transport.
					 */
					fs_io_close(io);
				}
			}
			io->last_connect_attempt = ts.tv_sec;
		}
	}
}

static void
fs_io_flush_output(struct fstrm_io *io)
{
	unsigned i;

	/* Do the actual write. */
	if (likely(io->writable && io->iov_idx > 0))
		fs_io_write_data(io, io->iov_array, io->iov_idx, io->iov_bytes);

	/* Perform the deferred deallocations. */
	for (i = 0; i < io->qe_idx; i++)
		fs_entry_free_bytes(&io->qe_array[i]);

	/* Zero counters and indices. */
	io->iov_bytes = 0;
	io->iov_idx = 0;
	io->qe_idx = 0;
}

static void
fs_io_maybe_flush_output(struct fstrm_io *io, size_t n_bytes)
{
	assert(io->iov_idx <= io->opt.iovec_size);
	if (io->iov_idx > 0) {
		if (io->iov_idx == io->opt.iovec_size ||
		    io->iov_bytes + n_bytes >= io->opt.buffer_hint)
		{
			/*
			 * If the scatter/gather array is full, or there are
			 * more than 'buffer_hint' bytes of data ready to be
			 * sent, flush the output.
			 */
			fs_io_flush_output(io);
		}
	}
}

static void
fs_io_process_queue_entry(struct fstrm_io *io, struct fs_queue_entry *entry)
{
	if (likely(io->writable)) {
		size_t n_bytes = sizeof(entry->be32_len) + ntohl(entry->be32_len);

		fs_io_maybe_flush_output(io, n_bytes);

		/* Copy the entry to the array of outstanding queue entries. */
		io->qe_array[io->qe_idx] = *entry;
		entry = &io->qe_array[io->qe_idx];
		io->qe_idx++;

		/* Add an iovec for the length of this payload. */
		io->iov_array[io->iov_idx].iov_base = (void *) &entry->be32_len;
		io->iov_array[io->iov_idx].iov_len = sizeof(entry->be32_len);
		io->iov_idx++;

		/* Add an iovec for the payload itself. */
		io->iov_array[io->iov_idx].iov_base = (void *) entry->bytes;
		io->iov_array[io->iov_idx].iov_len = ntohl(entry->be32_len);
		io->iov_idx++;

		/* There are now n_bytes more data waiting to be sent. */
		io->iov_bytes += n_bytes;
	} else {
		/* No writer is connected, just discard the payload. */
		fs_entry_free_bytes(entry);
	}
}

static unsigned
fs_io_process_queues(struct fstrm_io *io)
{
	struct fs_queue_entry entry;
	unsigned i;
	unsigned total = 0;

	/*
	 * Remove queue entries from each thread's circular queue, and add them
	 * to our buffer.
	 */
	for (i = 0; i < io->opt.num_queues; i++) {
		if (io->queue_ops->remove(io->queues[i].q, &entry, NULL)) {
			fs_io_process_queue_entry(io, &entry);
			total++;
		}
	}

	return total;
}

static void *
fs_io_thr(void *arg)
{
	struct fstrm_io *io = (struct fstrm_io *) arg;

	fs_io_thr_setup();
	fs_io_maybe_connect(io);

	for (;;) {
		int res;
		unsigned count;

		if (unlikely(io->shutting_down)) {
			while (fs_io_process_queues(io));
			fs_io_flush_output(io);
			fs_io_write_control_stop(io);
			fs_io_close(io);
			break;
		}

		fs_io_maybe_connect(io);

		count = fs_io_process_queues(io);
		if (count != 0)
			continue;

		res = fs_pthread_cond_timedwait(io->clkid_pthread,
						&io->cv, &io->cv_lock,
						io->opt.flush_timeout);
		if (res == ETIMEDOUT)
			fs_io_flush_output(io);
	}

	return NULL;
}
