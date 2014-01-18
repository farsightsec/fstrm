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

#include "fstrm-private.h"

#define FS_DEFAULT_NUM_QUEUES			1	/* queues */
#define FS_DEFAULT_BUFFER_HINT			8192	/* bytes */
#define FS_DEFAULT_FLUSH_TIMEOUT		1000	/* milliseconds */
#define FS_DEFAULT_IOVEC_SIZE			64	/* struct iovec's */
#define FS_DEFAULT_QUEUE_NOTIFY_THRESHOLD	32	/* entries */
#define FS_DEFAULT_QUEUE_LENGTH			512	/* entries */
#define FS_DEFAULT_RECONNECT_INTERVAL		5000	/* milliseconds */

struct fstrm_io_options default_fstrm_io_options = {
	.content_type =			NULL,
	.len_content_type =		0,
	.buffer_hint =			FS_DEFAULT_BUFFER_HINT,
	.flush_timeout =		FS_DEFAULT_FLUSH_TIMEOUT,
	.iovec_size =			FS_DEFAULT_IOVEC_SIZE,
	.num_queues =			FS_DEFAULT_NUM_QUEUES,
	.queue_length =			FS_DEFAULT_QUEUE_LENGTH,
	.queue_notify_threshold =	FS_DEFAULT_QUEUE_NOTIFY_THRESHOLD,
	.reconnect_interval =		FS_DEFAULT_RECONNECT_INTERVAL,
};

void
fs_io_options_dup(struct fstrm_io_options *out, const struct fstrm_io_options *opt)
{
	memmove(out, opt, sizeof(*out));
	if (out->content_type != NULL) {
		out->content_type = my_calloc(1, out->len_content_type);
		memmove(out->content_type,
			opt->content_type,
			out->len_content_type);
	}
}

struct fstrm_io_options *
fstrm_io_options_init(void)
{
	struct fstrm_io_options *opt;
	opt = my_calloc(1, sizeof(*opt));
	memmove(opt, &default_fstrm_io_options, sizeof(*opt));
	return opt;
}

void
fstrm_io_options_destroy(struct fstrm_io_options **opt)
{
	if (*opt != NULL) {
		free((*opt)->content_type);
		memset(*opt, 0, sizeof(**opt));
		free(*opt);
		*opt = NULL;
	}
}

void
fstrm_io_options_set_buffer_hint(struct fstrm_io_options *opt,
				 unsigned buffer_hint)
{
	assert(opt != NULL);
	opt->buffer_hint = buffer_hint;
}

void
fstrm_io_options_set_content_type(struct fstrm_io_options *opt,
				  const void *content_type,
				  size_t len_content_type)
{
	assert(opt != NULL);
	if (opt->content_type != NULL)
		free(opt->content_type);
	opt->content_type = my_calloc(1, len_content_type);
	opt->len_content_type = len_content_type;
	memmove(opt->content_type, content_type, len_content_type);
}

void
fstrm_io_options_set_flush_timeout(struct fstrm_io_options *opt,
				   unsigned flush_timeout)
{
	assert(opt != NULL);
	opt->flush_timeout = flush_timeout;
}

void
fstrm_io_options_set_iovec_size(struct fstrm_io_options *opt,
				unsigned iovec_size)
{
	assert(opt != NULL);
	opt->iovec_size = iovec_size;
}

void
fstrm_io_options_set_num_queues(struct fstrm_io_options *opt,
				unsigned num_queues)
{
	assert(opt != NULL);
	opt->num_queues = num_queues;
}

void
fstrm_io_options_set_queue_length(struct fstrm_io_options *opt,
				  unsigned queue_length)
{
	assert(opt != NULL);
	opt->queue_length = queue_length;
}

void
fstrm_io_options_set_reconnect_interval(struct fstrm_io_options *opt,
					unsigned reconnect_interval)
{
	assert(opt != NULL);
	opt->reconnect_interval = reconnect_interval;
}

void
fstrm_io_options_set_writer(struct fstrm_io_options *opt,
			    const struct fstrm_writer *writer,
			    const void *writer_options)
{
	assert(opt != NULL);
	if (opt->writer != NULL)
		free(opt->writer);
	opt->writer = my_calloc(1, sizeof(struct fstrm_writer));
	memmove(opt->writer, writer, sizeof(struct fstrm_writer));
	opt->writer_options = writer_options;
}

bool
fs_io_options_validate(const struct fstrm_io_options *opt, char **errstr_out)
{
	const char *err = NULL;

	if (opt == NULL) {
		err = "non-NULL options parameter required";
		goto out;
	}

	if (opt->writer != NULL) {
		if (!opt->writer->create ||
		    !opt->writer->destroy ||
		    !opt->writer->open ||
		    !opt->writer->close ||
		    !opt->writer->is_opened ||
		    !opt->writer->write_control ||
		    !opt->writer->write_data)
		{
			err = "missing writer method";
			goto out;
		}
	} else {
		err = "writer parameter required";
		goto out;
	}

	if (opt->buffer_hint < 1024 || opt->buffer_hint > 65536) {
		err = "buffer_hint out of allowed range [1024..65536]";
		goto out;
	}

	if (opt->flush_timeout < 1 || opt->flush_timeout > 60000) {
		err = "flush_timeout out of allowed range [1..60000]";
		goto out;
	}

	if (opt->iovec_size & 1) {
		err = "iovec_size must be a multiple of 2";
		goto out;
	}
	
	if (opt->iovec_size > IOV_MAX) {
		err = "iovec_size greater than IOV_MAX";
		goto out;
	}

	if (opt->num_queues < 1) {
		err = "num_queues must be at least 1";
		goto out;
	}

	if (opt->queue_length < 2 || opt->queue_length > 16384) {
		err = "queue_length out of allowed range [2..16384]";
		goto out;
	}

	if (((opt->queue_length - 1) & opt->queue_length) != 0) {
		err = "queue_length must be a power of 2";
		goto out;
	}

	if (opt->queue_notify_threshold < 1 ||
	    opt->queue_notify_threshold >= opt->queue_length - 1)
	{
		err = "queue_notify_threshold out of allowed range [1..queue_length-1]";
		goto out;
	}

	if (opt->reconnect_interval < 1000 || opt->reconnect_interval > 60000) {
		err = "reconnect_interval out of allowed range [1000..60000]";
		goto out;
	}

out:
	if (err != NULL) {
		if (errstr_out != NULL)
			*errstr_out = my_strdup(err);
		return false;
	}

	return true;
}
