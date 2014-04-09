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

/*! \file
 * \mainpage Introduction
 *
 * This is `fstrm`, a C implementation of the Frame Streams data transport
 * protocol.
 *
 * Frame Streams is a light weight, binary clean protocol that allows for the
 * transport of arbitrarily encoded data payload sequences with minimal framing
 * overhead -- just four bytes per data frame. Frame Streams does not specify an
 * encoding format for data frames and can be used with any data serialization
 * format that produces byte sequences, such as [Protocol Buffers], [XML],
 * [JSON], [MessagePack], [YAML], etc. Frame Streams can be used as both a
 * streaming transport over a reliable byte stream socket (TCP sockets, TLS
 * connections, `AF_UNIX` sockets, etc.) for data in motion as well as a file
 * format for data at rest. A "Content Type" header identifies the type of
 * payload being carried over an individual Frame Stream and allows cooperating
 * programs to determine how to interpret a given sequence of data payloads.
 *
 * `fstrm` is an optimized C implementation of Frame Streams that includes a
 * fast, lockless circular queue implementation and exposes library interfaces
 * for setting up a dedicated Frame Streams I/O thread and asynchronously
 * submitting data frames for transport from worker threads. It was originally
 * written to facilitate the addition of high speed binary logging to DNS
 * servers written in C using the [dnstap] log format.
 *
 * This is the API documentation for the `fstrm` library. For the project
 * hosting site, see <https://github.com/farsightsec/fstrm>.
 *
 * \authors Farsight Security, Inc. and the `fstrm` authors.
 *
 * \copyright 2013-2014. Licensed under the terms of the [Apache-2.0] license.
 *
 * [Protocol Buffers]: https://developers.google.com/protocol-buffers/
 * [XML]:              http://www.w3.org/TR/xml11/
 * [JSON]:             http://www.json.org/
 * [MessagePack]:      http://msgpack.org/
 * [YAML]:             http://www.yaml.org/
 * [dnstap]:           http://dnstap.info/
 * [Apache-2.0]:       http://www.apache.org/licenses/LICENSE-2.0
 *
 * \page overview Library overview
 *
 * \section init Initializing the library
 *
 * `fstrm` has no global library state. In most cases, only a single `fstrm_io`
 * library context object will be needed for the entire process, which will
 * implicitly create a background I/O serialization thread. This I/O thread is
 * bound to a particular output (for example, an `AF_UNIX` socket) and is fully
 * buffered -- submitted data frames will be accumulated in an output buffer and
 * periodically flushed, minimizing the number of system calls that need to be
 * performed.
 *
 * In order to create the `fstrm_io` library context object, the caller first
 * needs to create an `fstrm_io_options` object which will be used to set any
 * needed options, and then pass this options object to the fstrm_io_init()
 * function. This options object may then be immediately destroyed after the
 * `fstrm_io` object has been successfully created. See the \ref fstrm_io module
 * documentation for a detailed list of the options that can be set on an
 * `fstrm_io` object.
 *
 * Most of the settings which can be configured for an `fstrm_io` object are
 * optional, except for the `writer` parameter, which is required. See the
 * fstrm_io_options_set_writer() function and the \ref fstrm_writer module
 * documentation for details. `fstrm_writer` is an abstract interface that can
 * be used to connect a byte stream output into the `fstrm_io` processing loop.
 * Several concrete implementations of the `fstrm_writer` interface are included
 * in `libfstrm`, such as \ref fstrm_file_writer, which writes its output to a
 * regular file, and \ref fstrm_unix_writer, which writes its output to a
 * stream-oriented `AF_UNIX` socket.
 *
 * The following code example shows the initialization of the `fstrm_io` library
 * context object connected to an `fstrm_file_writer` output.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	const char *file_path = "/tmp/output.fs";

	struct fstrm_file_writer_options *wopt;
	wopt = fstrm_file_writer_options_init();
	fstrm_file_writer_options_set_file_path(wopt, file_path);

	struct fstrm_io_options *fopt;
	fopt = fstrm_io_options_init();
	fstrm_io_options_set_writer(fopt, fstrm_file_writer, wopt);

	char *errstr = NULL;
	struct fstrm_io *fio;
	fio = fstrm_io_init(fopt, &errstr);
	if (!fio) {
		fprintf(stderr, "Error: fstrm_io_init() failed: %s\n", errstr);
		free(errstr);
		exit(EXIT_FAILURE);
	}
	fstrm_io_options_destroy(&fopt);
	fstrm_file_writer_options_destroy(&wopt);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \section queue Getting a queue
 *
 * After the `fstrm_io` object has been created with fstrm_io_init(), a queue
 * handle can be obtained with the fstrm_io_get_queue() function, which returns
 * an `fstrm_queue` object. This function is thread-safe and will return a
 * unique queue handle each time it is called, up to the number of queues
 * specified by fstrm_io_options_set_num_queues(). `fstrm_queue` objects belong
 * to their parent `fstrm_io` object and will be destroyed when the parent
 * `fstrm_io` object is destroyed.
 *
 * The following code example shows a single `fstrm_queue` handle being obtained
 * from an already initialized `fstrm_io` library context object.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// 'fio' is a struct fstrm_io *

	struct fstrm_queue *fq;
	fq = fstrm_io_get_queue(fio);
	if (!fq) {
		fprintf(stderr, "Error: fstrm_io_get_queue() failed.\n");
		exit(EXIT_FAILURE);
	}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \section submit Submitting data frames
 *
 * Once the `fstrm_io` object has been created and an `fstrm_queue` handle is
 * available, data frames can be submitted for asynchronous writing using the
 * fstrm_io_submit() function. A callback is passed through this function which
 * will be invoked to deallocate the data frame once the I/O thread has
 * completed processing it. In the common case where the data frame is
 * dynamically allocated with `malloc()`, the deallocation callback must call
 * `free()`. fstrm_free_wrapper() is provided as a convenience function which
 * does this.
 *
 * If space is available in the queue, fstrm_io_submit() will return
 * #FSTRM_RES_SUCCESS, indicating that ownership of the memory allocation for the
 * data frame has passed from the caller to the library. The caller must not
 * reuse or deallocate the memory for the data frame after a successful call to
 * fstrm_io_submit().
 *
 * Callers must check the return value of fstrm_io_submit(). If this function
 * fails, that is, it returns any result code other than #FSTRM_RES_SUCCESS, the
 * caller must deallocate or otherwise dispose of memory allocated for the data
 * frame, in order to avoid leaking memory. fstrm_io_submit() can fail with
 * #FSTRM_RES_AGAIN if there is currently no space in the circular queue for an
 * additional frame, in which case a later call to fstrm_io_submit() with the
 * same parameters may succeed. However, if fstrm_io_submit() fails with
 * #FSTRM_RES_INVALID, then there is a problem with the parameters and a later
 * call will not succeed.
 *
 * The following code example shows data frames containing a short sequence of
 * bytes being created and submitted repeatedly, with appropriate error
 * handling.  Note that the data frames in this example intentionally contain
 * embedded unprintable characters, showing that Frame Streams is binary clean.
 * This example follows from the previous examples, where the `fio` and `fq`
 * variables have already been initialized.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// 'fio' is a struct fstrm_io *
	// 'fq' is a struct fstrm_queue *

	const unsigned num_frames = 100;
	const uint8_t frame_template[] = {
		'H', 'e', 'l', 'l', 'o',
		0x00, 0x01, 0x02, 0x03,
		'W', 'o', 'r', 'l', 'd',
		0x04, 0x05, 0x06, 0x07,
	};

	for (unsigned i = 0; i < num_frames; i++) {
		// Allocate a new frame from the template.
		uint8_t *frame = malloc(sizeof(frame_template));
		if (!frame)
			break;
		memcpy(frame, frame_template, sizeof(frame_template));

		// Submit the frame for writing.
		for (;;) {
			fstrm_res res;
			res = fstrm_io_submit(fio, fq, frame,
					      sizeof(frame_template),
					      fstrm_free_wrapper, NULL);
			if (res == FSTRM_RES_SUCCESS) {
				// Frame successfully queued.
				break;
			} else if (res == FSTRM_RES_AGAIN) {
				// Queue is full. Try again in a busy loop.
				continue;
			} else {
				// Permanent failure.
				free(frame);
				fputs("fstrm_io_submit() failed.\n", stderr);
				break;
			}
		}
	}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \section shutdown Shutting down
 *
 * Calling fstrm_io_destroy() on the `fstrm_io` object will signal the I/O
 * thread to flush any outstanding data frames being written and will deallocate
 * all associated resources. This function is synchronous and does not return
 * until the I/O thread has terminated.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// 'fio' is a struct fstrm_io *
	fstrm_io_destroy(&fio);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef FSTRM_H
#define FSTRM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/uio.h>
#include <stddef.h>

#define FSTRM_DEFAULT_IO_NUM_QUEUES		1	/* queues */
#define FSTRM_DEFAULT_IO_BUFFER_HINT		8192	/* bytes */
#define FSTRM_DEFAULT_IO_FLUSH_TIMEOUT		1	/* seconds */
#define FSTRM_DEFAULT_IO_IOVEC_SIZE		64	/* struct iovec's */
#define FSTRM_DEFAULT_IO_QUEUE_NOTIFY_THRESHOLD	32	/* queue entries */
#define FSTRM_DEFAULT_IO_QUEUE_LENGTH		512	/* queue entries */
#define FSTRM_DEFAULT_IO_RECONNECT_INTERVAL	5	/* seconds */

#define FSTRM_CONTROL_ACCEPT			0x01
#define FSTRM_CONTROL_START			0x02
#define FSTRM_CONTROL_STOP			0x03

#define FSTRM_CONTROL_FIELD_CONTENT_TYPE	0x01

struct fstrm_io;
struct fstrm_io_options;
struct fstrm_queue;
struct fstrm_writer;
struct fstrm_writer_options;

/* fstrm_res */

typedef enum {
	FSTRM_RES_SUCCESS,
	FSTRM_RES_FAILURE,
	FSTRM_RES_AGAIN,
	FSTRM_RES_INVALID,
} fstrm_res;

/* fstrm_queue_model */

typedef enum {
	FSTRM_QUEUE_MODEL_SPSC, /* Single Producer, Single Consumer */
	FSTRM_QUEUE_MODEL_MPSC,	/* Multiple Producer, Single Consumer */
} fstrm_queue_model;

#define FSTRM_DEFAULT_IO_QUEUE_MODEL	FSTRM_QUEUE_MODEL_SPSC

/* fstrm_io */

struct fstrm_io *
fstrm_io_init(const struct fstrm_io_options *, char **err);

void
fstrm_io_destroy(struct fstrm_io **);

struct fstrm_queue *
fstrm_io_get_queue(struct fstrm_io *);

fstrm_res
fstrm_io_submit(struct fstrm_io *, struct fstrm_queue *,
		void *buf, size_t len,
		void (*free_func)(void *buf, void *free_data),
		void *free_data);

void
fstrm_free_wrapper(void *buf, void *free_data);

/* fstrm_io_options */

struct fstrm_io_options *
fstrm_io_options_init(void);

void
fstrm_io_options_destroy(struct fstrm_io_options **);

void
fstrm_io_options_set_buffer_hint(
	struct fstrm_io_options *,
	unsigned buffer_hint);

void
fstrm_io_options_set_content_type(
	struct fstrm_io_options *,
	const void *buf, size_t len);

void
fstrm_io_options_set_flush_timeout(
	struct fstrm_io_options *,
	unsigned flush_timeout);

void
fstrm_io_options_set_iovec_size(
	struct fstrm_io_options *,
	unsigned iovec_size);

void
fstrm_io_options_set_num_queues(
	struct fstrm_io_options *,
	unsigned num_queues);

void
fstrm_io_options_set_queue_length(
	struct fstrm_io_options *,
	unsigned queue_length);

void
fstrm_io_options_set_queue_model(
	struct fstrm_io_options *,
	fstrm_queue_model);

void
fstrm_io_options_set_queue_notify_threshold(
	struct fstrm_io_options *,
	unsigned queue_notify_threshold);

void
fstrm_io_options_set_reconnect_interval(
	struct fstrm_io_options *,
	unsigned reconnect_interval);

void
fstrm_io_options_set_writer(
	struct fstrm_io_options *,
	const struct fstrm_writer *,
	const void *writer_options);

/* fstrm_writer */

typedef fstrm_res (*fstrm_writer_create_func)(
	struct fstrm_io *,
	const struct fstrm_writer_options *,
	void **data);

typedef fstrm_res (*fstrm_writer_destroy_func)(void *);

typedef fstrm_res (*fstrm_writer_open_func)(void *);

typedef fstrm_res (*fstrm_writer_close_func)(void *);

typedef fstrm_res (*fstrm_writer_write_func)(void *,
					     struct iovec *, int iovcnt,
					     unsigned nbytes);

struct fstrm_writer *
fstrm_writer_init(void);

void
fstrm_writer_destroy(struct fstrm_writer **);

void
fstrm_writer_set_create(
	struct fstrm_writer *,
	fstrm_writer_create_func);

void
fstrm_writer_set_destroy(
	struct fstrm_writer *,
	fstrm_writer_destroy_func);

void
fstrm_writer_set_open(
	struct fstrm_writer *,
	fstrm_writer_open_func);

void
fstrm_writer_set_close(
	struct fstrm_writer *,
	fstrm_writer_close_func);

void
fstrm_writer_set_write_control(
	struct fstrm_writer *,
	fstrm_writer_write_func);

void
fstrm_writer_set_write_data(
	struct fstrm_writer *,
	fstrm_writer_write_func);

/* fstrm_file_writer, fstrm_file_writer_options */

extern const struct fstrm_writer *fstrm_file_writer;

struct fstrm_file_writer_options *
fstrm_file_writer_options_init(void);

void
fstrm_file_writer_options_destroy(
	struct fstrm_file_writer_options **);

void
fstrm_file_writer_options_set_file_path(
	struct fstrm_file_writer_options *,
	const char *file_path);

/* fstrm_unix_writer, fstrm_unix_writer_options */

extern const struct fstrm_writer *fstrm_unix_writer;

struct fstrm_unix_writer_options *
fstrm_unix_writer_options_init(void);

void
fstrm_unix_writer_options_destroy(
	struct fstrm_unix_writer_options **);

void
fstrm_unix_writer_options_set_socket_path(
	struct fstrm_unix_writer_options *,
	const char *socket_path);

#ifdef __cplusplus
}
#endif

#endif /* FSTRM_H */

