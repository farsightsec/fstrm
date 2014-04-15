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

struct fstrm_io;
struct fstrm_io_options;
struct fstrm_queue;
struct fstrm_writer;
struct fstrm_writer_options;

/**
 * \defgroup constants Macros and constants
 * @{
 */

/**
 * Result codes for functions.
 */
typedef enum {
	/** Success. */
	FSTRM_RES_SUCCESS,

	/** Failure. */
	FSTRM_RES_FAILURE,

	/** Resource temporarily unavailable. */
	FSTRM_RES_AGAIN,

	/** Parameters were invalid. */
	FSTRM_RES_INVALID,
} fstrm_res;

/**
 * Queue models.
 * \see fstrm_io_options_set_queue_model()
 */
typedef enum {
	/** Single Producer, Single Consumer. */
	FSTRM_QUEUE_MODEL_SPSC,

	/** Multiple Producer, Single Consumer. */
	FSTRM_QUEUE_MODEL_MPSC,
} fstrm_queue_model;

/**
 * Default queue model.
 * \see fstrm_io_options_set_queue_model()
 */
#define FSTRM_DEFAULT_IO_QUEUE_MODEL		FSTRM_QUEUE_MODEL_SPSC

/**
 * Default number of I/O queues.
 * \see fstrm_io_options_set_num_queues()
 */
#define FSTRM_DEFAULT_IO_NUM_QUEUES		1

/**
 * Default I/O buffer hint size in bytes.
 * \see fstrm_io_options_set_buffer_hint()
 */
#define FSTRM_DEFAULT_IO_BUFFER_HINT		8192

/**
 * Default I/O flush timeout in seconds.
 * \see fstrm_io_options_set_flush_timeout()
 */
#define FSTRM_DEFAULT_IO_FLUSH_TIMEOUT		1

/**
 * Default size of `iovec` array.
 * \see fstrm_io_options_set_iovec_size()
 */
#define FSTRM_DEFAULT_IO_IOVEC_SIZE		64

/**
 * Default number of outstanding queue entries before waking up the I/O thread.
 * \see fstrm_io_options_set_queue_notify_threshold()
 *
 */
#define FSTRM_DEFAULT_IO_QUEUE_NOTIFY_THRESHOLD	32

/**
 * Default length of the I/O queue.
 * \see fstrm_io_options_set_queue_length()
 */
#define FSTRM_DEFAULT_IO_QUEUE_LENGTH		512

/**
 * Default interval between I/O reconnection attempts in seconds.
 * \see fstrm_io_options_set_reconnect_interval()
 */
#define FSTRM_DEFAULT_IO_RECONNECT_INTERVAL	5

/** Control type value for "Accept" control frames. */
#define FSTRM_CONTROL_ACCEPT			0x01

/** Control type value for "Start" control frames. */
#define FSTRM_CONTROL_START			0x02

/** Control type value for "Stop" control frames. */
#define FSTRM_CONTROL_STOP			0x03

/** Field type value for the "content type" control frame option. */
#define FSTRM_CONTROL_FIELD_CONTENT_TYPE	0x01

/**
 * The maximum length in bytes of an "Accept", "Start", or "Stop" control frame,
 * excluding the escape sequence and the control frame length.
 */
#define FSTRM_MAX_CONTROL_FRAME_LENGTH		512

/**@}*/

/*!
 * \defgroup fstrm_io fstrm_io
 *
 * The `fstrm_io` interface creates a background I/O thread which writes
 * Frame Streams encapsulated data frames into an output stream specified by an
 * \ref fstrm_writer. Parameters used to configure the I/O thread are passed
 * through an `fstrm_io_options` object.
 *
 * A number of parameters for configuring an individual `fstrm_io` object can be
 * provided through an `fstrm_io_options` object. Most of these parameters are
 * performance knobs which have reasonable defaults and will generally not need
 * to be configured by most `fstrm_io` users. However, there is no default for
 * the `writer` parameter, which specifies a concrete implementation for writing
 * Frame Streams content to an output stream (such as \ref fstrm_file_writer or
 * \ref fstrm_unix_writer). This parameter must be set with the
 * fstrm_io_options_set_writer() function. Custom writers may be implemented
 * through the \ref fstrm_writer interface.
 *
 * `fstrm_io` users may also want to use the fstrm_io_options_set_content_type()
 * function to embed a "Content Type" value in the Frame Streams output. This
 * value can be used to describe the encoding of data frames. For instance, if
 * data frames are being encoded using Protocol Buffers, the Frame Streams
 * "Content Type" might specify the package-qualified name of a top-level
 * Protocol Buffers message type. (E.g., `dnstap` uses a Content Type of
 * `"protobuf:dnstap.Dnstap"`.) Or, if data frames are encoded with XML, the
 * Frame Streams "Content Type" might specify a URL to an XML schema.
 *
 * @{
 */

/**
 * Initialize an `fstrm_io` object. This creates a background I/O thread which
 * asynchronously writes data payloads submitted by other threads which call
 * fstrm_io_submit().
 *
 * fstrm_io_init() must receive an options object created by
 * fstrm_io_options_init(), and this options object must specify an \ref
 * fstrm_writer to use to write data frames into. See
 * fstrm_io_options_set_writer().
 *
 * The options object used in the initialization of an `fstrm_io` object may be
 * destroyed with fstrm_io_options_destroy() after fstrm_io_init() returns.
 *
 * This function performs sanity checking of the options specified via the `opt`
 * parameter and will return an error string if any of these checks fail.
 *
 * \param[in] opt
 *      I/O options, created by fstrm_io_options_init(). Must be non-NULL.
 * \param[out] err
 *      Error string return pointer.
 *
 * \return
 *      An `fstrm_io` context object which is non-NULL on success or NULL on
 *      failure. On failure, if `err` was non-NULL, `*err` will point to a
 *      malloc'd error string describing the reason for failure.
 */
struct fstrm_io *
fstrm_io_init(const struct fstrm_io_options *opt, char **err);

/**
 * Destroy an `fstrm_io` object. This signals the background I/O thread to
 * flush or discard any queued data frames and deallocates any resources used
 * internally. This function is synchronous and waits for the I/O thread to
 * terminate before returning.
 *
 * The \ref fstrm_writer used by the `fstrm_io` object will have its `destroy`
 * method invoked by a call to fstrm_io_destroy().
 *
 * \param[in] io
 *      Pointer to an `fstrm_io` object.
 */
void
fstrm_io_destroy(struct fstrm_io **io);

/**
 * Obtain an `fstrm_queue` object for submitting data frames to the `fstrm_io`
 * object. `fstrm_queue` objects are child objects of their parent `fstrm_io`
 * object and will be destroyed when fstrm_io_destroy() is called on the parent
 * `fstrm_io` object.
 *
 * This function is thread-safe and may be called simultaneously from any
 * thread. For example, in a program which employs worker threads to handle
 * requests, fstrm_io_get_queue() may be called from a thread startup routine
 * without synchronization.
 *
 * `fstrm_io` objects allocate a fixed total number of `fstrm_queue` objects at
 * the time of a call to fstrm_io_init(). To adjust this number, use
 * fstrm_io_options_set_num_queues(). This function will fail if it is called
 * more than the number of times allowed by this option. By default, only one
 * queue is initialized per `fstrm_io` object.
 *
 * For optimum performance in a threaded program, each worker thread submitting
 * data frames should have a dedicated `fstrm_queue` object. This allows each
 * worker thread to have its own queue which is processed independently by the
 * I/O thread. If the queue model for the `fstrm_io` object is set to
 * #FSTRM_QUEUE_MODEL_SPSC, this avoids the need for synchronized access to the
 * queue.
 *
 * \param fio
 *      `fstrm_io` object.
 *
 * \return
 *      An `fstrm_queue` object which is non-NULL on success and NULL on failure.
 */
struct fstrm_queue *
fstrm_io_get_queue(struct fstrm_io *fio);

/**
 * Submit a data frame to the background I/O thread. If successfully queued and
 * the I/O thread has an active output stream opened, the data frame will be
 * asynchronously written to the output stream.
 *
 * When this function returns #FSTRM_RES_SUCCESS, responsibility for
 * deallocating the data frame specified by the `buf` parameter passes to the
 * `fstrm` library. The caller **MUST** ensure that the `buf` object remains valid
 * after fstrm_io_submit() returns. The callback function specified by the
 * `free_func` parameter will be invoked once the data frame is no longer needed
 * by the `fstrm` library. For example, if the data frame is dynamically
 * allocated, the caller may deallocate the data frame in the callback function.
 *
 * As a convenience, if `buf` is allocated with the system's `malloc()`,
 * `fstrm_free_wrapper` may be provided as the `free_func` parameter with the
 * `free_data` parameter set to `NULL`. This will cause the system's `free()` to
 * be invoked to deallocate `buf`.
 *
 * `free_func` may be NULL, in which case no callback function will be invoked
 * to dispose of `buf`. This behavior may be useful if `buf` is a global,
 * statically allocated object.
 *
 * \param fio
 *      `fstrm_io` object.
 * \param fq
 *      `fstrm_queue` object.
 * \param buf
 *      Data frame bytes.
 * \param len
 *      Number of data frame bytes in `buf`.
 * \param free_func
 *      Callback function to deallocate the data frame. The `buf` and
 *      `free_data` parameters passed to this callback will be the same values
 *      originally supplied to fstrm_io_submit().
 * \param free_data
 *      Parameter to pass to `free_func`.
 *
 * \return FSTRM_RES_SUCCESS
 *      The data frame was successfully queued.
 * \return FSTRM_RES_AGAIN
 *      The queue is full.
 * \return FSTRM_RES_FAILURE
 *      Permanent failure.
 */
fstrm_res
fstrm_io_submit(struct fstrm_io *fio, struct fstrm_queue *fq,
		void *buf, size_t len,
		void (*free_func)(void *buf, void *free_data),
		void *free_data);

/**
 * Wrapper function for the system's `free()` function suitable for use as a
 * callback to fstrm_io_submit().
 *
 * \param buf
 *      Object to call `free() on`.
 * \param free_data
 *      Unused.
 */
void
fstrm_free_wrapper(void *buf, void *free_data);

/**
 * Initialize an `fstrm_io_options` object, which is needed by fstrm_io_init().
 *
 * \return
 *      An `fstrm_io_options` object which is always non-NULL.
 */
struct fstrm_io_options *
fstrm_io_options_init(void);

/**
 * Destroy an `fstrm_io_options` object.
 *
 * \param fopt
 *      Pointer to the `fstrm_io_options` object.
 */
void
fstrm_io_options_destroy(struct fstrm_io_options **fopt);

/**
 * Set the `buffer_hint` option. This is the threshold number of bytes to
 * accumulate in the output buffer before forcing a buffer flush.
 *
 * Allowed range: 1024 - 65536 bytes.
 *
 * \see FSTRM_DEFAULT_IO_BUFFER_HINT
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param buffer_hint
 *      New `buffer_hint` value.
 */
void
fstrm_io_options_set_buffer_hint(
	struct fstrm_io_options *fopt,
	unsigned buffer_hint);

/**
 * Set the `content_type` option. This is a byte string identifying the type of
 * data frames that will be carried over the Frame Streams output and is
 * embedded in a control frame at the start of the Frame Streams output.
 *
 * The byte string passed in `buf` will be copied.
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param buf
 *      Byte buffer.
 * \param len
 *      Number of bytes pointed to by `buf`.
 */
void
fstrm_io_options_set_content_type(
	struct fstrm_io_options *fopt,
	const void *buf, size_t len);

/**
 * Set the `flush_timeout` option. This is the number of seconds to allow
 * unflushed data to remain in the output queue.
 *
 * Allowed range: 1 - 600 seconds.
 *
 * \see FSTRM_DEFAULT_IO_FLUSH_TIMEOUT
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param flush_timeout
 *      New `flush_timeout` value.
 */
void
fstrm_io_options_set_flush_timeout(
	struct fstrm_io_options *fopt,
	unsigned flush_timeout);

/**
 * Set the `iovec_size` option. This is the size of the `iovec` array used to
 * accumulate data in the output queue.
 *
 * Allowed range: 2 - `IOV_MAX`. Additionally, `iovec_size` must be a power of
 * two.
 *
 * \see FSTRM_DEFAULT_IO_IOVEC_SIZE
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param iovec_size
 *      New `iovec_size` value.
 */
void
fstrm_io_options_set_iovec_size(
	struct fstrm_io_options *fopt,
	unsigned iovec_size);

/**
 * Set the `num_queues` option. This is the number of input queues to create and
 * should match the number of times that fstrm_io_get_queue() is called on the
 * corresponding `fstrm_io` object.
 *
 * Allowed range: `num_queues` must be positive.
 *
 * \see FSTRM_DEFAULT_IO_NUM_QUEUES
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param num_queues
 *      New `num_queues` value.
 */
void
fstrm_io_options_set_num_queues(
	struct fstrm_io_options *fopt,
	unsigned num_queues);

/**
 * Set the `queue_length` option. This is the number of queue entries to
 * allocate for each input queue. This option controls the number of outstanding
 * data frames that can be enqueued for deferred processing by the I/O thread
 * and thus affects performance and memory usage.
 *
 * Allowed range: 2 - 16384 queue entries. Additionally, `queue_length` must be
 * a power of two.
 *
 * \see FSTRM_DEFAULT_IO_QUEUE_LENGTH
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param queue_length
 *      New `queue_length` value.
 */
void
fstrm_io_options_set_queue_length(
	struct fstrm_io_options *fopt,
	unsigned queue_length);

/**
 * Set the `queue_model` option. This controls what queueing semantics to use
 * for `fstrm_queue` objects. Single Producer queues (#FSTRM_QUEUE_MODEL_SPSC)
 * may only have a single thread at a time calling fstrm_io_submit() on a given
 * `fstrm_queue` object, while Multiple Producer queues
 * (#FSTRM_QUEUE_MODEL_MPSC) may have multiple threads simultaneously calling
 * fstrm_io_submit() on a given `fstrm_queue` object.
 *
 * \see fstrm_queue_model
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param queue_model
 *      New `queue_model` value.
 */
void
fstrm_io_options_set_queue_model(
	struct fstrm_io_options *fopt,
	fstrm_queue_model queue_model);

/**
 * Set the `queue_notify_threshold` option. This controls the number of
 * outstanding queue entries to allow on an input queue before waking the I/O
 * thread, which will cause the input queue entries to begin draining.
 *
 * Allowed range: 1 - (`queue_length` - 1) entries.
 *
 * \see FSTRM_DEFAULT_IO_QUEUE_NOTIFY_THRESHOLD
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param queue_notify_threshold
 *      New `queue_notify_threshold` value.
 */
void
fstrm_io_options_set_queue_notify_threshold(
	struct fstrm_io_options *fopt,
	unsigned queue_notify_threshold);

/**
 * Set the `reconnect_interval` option. This controls the number of seconds
 * between attempts to reopen a closed output stream.
 *
 * Allowed range: 1 - 600 seconds.
 *
 * \see FSTRM_DEFAULT_IO_RECONNECT_INTERVAL
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param reconnect_interval
 *      New `reconnect_interval` value.
 */
void
fstrm_io_options_set_reconnect_interval(
	struct fstrm_io_options *fopt,
	unsigned reconnect_interval);

/**
 * Set the `writer` implementation to use for the output stream. This specifies
 * the concrete implementation that will be used to write Frame Streams data.
 *
 * Several concrete implementations are provided in the `fstrm` library.
 * \ref fstrm_file_writer writes output to a regular file, while
 * \ref fstrm_unix_writer writes output to an `AF_UNIX` socket. To use one of
 * these concrete implementations, for example, \ref fstrm_unix_writer, specify
 * `fstrm_unix_writer` as the `writer` parameter to
 * fstrm_io_options_set_writer(), and pass an initialized
 * `fstrm_unix_writer_options` object as the `writer_options` parameter.
 *
 * \param fopt
 *      `fstrm_io_options` object.
 * \param writer
 *      \ref fstrm_writer object.
 * \param writer_options
 *      An opaque object that is passed to the `fstrm_writer` implementation.
 *      Used for configuring `fstrm_writer` implementation-specific options.
 *
 * \see \ref fstrm_writer
 * \see \ref fstrm_file_writer
 * \see \ref fstrm_unix_writer
 */
void
fstrm_io_options_set_writer(
	struct fstrm_io_options *fopt,
	const struct fstrm_writer *writer,
	const void *writer_options);

/**@}*/

/*!
 * \defgroup fstrm_writer fstrm_writer
 *
 * `fstrm_writer` is an interface for abstracting the process of writing to a
 * byte stream output. It allows extending the `fstrm` library to support
 * writing Frame Streams output to new kinds of byte stream outputs. It also
 * allows building mock outputs for testing the correct functioning of the
 * library.
 *
 * Several concrete implementations of the `fstrm_writer` interface are already
 * provided by the `fstrm` library that allow writing to file and `AF_UNIX`
 * socket outputs.
 *
 * A new concrete implementation can be defined by calling
 * fstrm_writer_init() and then providing the "methods" for the implementation
 * by passing function pointers via the fstrm_writer_set_create(),
 * fstrm_writer_set_destroy(), etc. functions. A concrete implementation of
 * `fstrm_writer` **MUST** provide the following "methods", which are further
 * described below:
 *
 * Method name       | Method type                | Method description
 * ----------------- | -------------------------- | ------------------
 * `create`          | #fstrm_writer_create_func  | Creates a new instance of the output.
 * `destroy`         | #fstrm_writer_destroy_func | Destroys an instance of the output.
 * `open`            | #fstrm_writer_open_func    | Opens the output and readies it for writing.
 * `close`           | #fstrm_writer_close_func   | Closes the output.
 * `write_control`   | #fstrm_writer_write_func   | Writes a Frame Streams control frame.
 * `write_data`      | #fstrm_writer_write_func   | Writes a Frame Streams data frame.
 *
 * The following code example shows how to construct an `fstrm_writer` given
 * implementations of these methods:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        extern fstrm_writer_create_func  my_writer_create;
        extern fstrm_writer_destroy_func my_writer_destroy;
        extern fstrm_writer_open_func    my_writer_open;
        extern fstrm_writer_close_func   my_writer_close;
        extern fstrm_writer_write_func   my_writer_write;
        extern fstrm_writer_write_func   my_writer_write;

        struct fstrm_writer *my_writer_impl;

        my_writer = fstrm_writer_init();
        fstrm_writer_set_create(my_writer_impl,        my_writer_create);
        fstrm_writer_set_destroy(my_writer_impl,       my_writer_destroy);
        fstrm_writer_set_open(my_writer_impl,          my_writer_open);
        fstrm_writer_set_close(my_writer_impl,         my_writer_close);
        fstrm_writer_set_write_data(my_writer_impl,    my_writer_write_data);
        fstrm_writer_set_write_control(my_writer_impl, my_writer_write_control);

        const struct fstrm_writer *my_writer = my_writer_impl;
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * At this point, the `my_writer` variable is now suitable as the `writer`
 * argument to fstrm_io_options_set_writer().
 *
 * The following code example follows on from the above example and shows dummy
 * implementations of the functions referenced above. This implementation
 * doesn't actually do anything with the data provided to it and is only meant
 * to show how to construct an implementation that conforms to the
 * `fstrm_writer` interface.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
struct my_writer_state;
struct my_writer_options;

fstrm_res
my_writer_create(struct fstrm_io *fio,
                 const struct fstrm_writer_options *wopt,
                 void **data)
{
        const struct my_writer_options *my_wopt =
                (const struct my_writer_options *) wopt;
        struct my_writer_state *state = calloc(1, sizeof(*state));
        if (!state)
                return FSTRM_RES_FAILURE;

        *data = state;
        return FSTRM_RES_SUCCESS;
}

fstrm_res
my_writer_destroy(void *data)
{
        struct my_writer_state *state = (struct my_writer_state *) data;
        free(state);
        return FSTRM_RES_SUCCESS;
}

fstrm_res
my_writer_open(void *data)
{
        struct my_writer_state *state = (struct my_writer_state *) data;
        return FSTRM_RES_SUCCESS;
}

fstrm_res
my_writer_close(void *data)
{
        struct my_writer_state *state = (struct my_writer_state *) data;
        return FSTRM_RES_SUCCESS;
}

fstrm_res
my_writer_write_data(void *data,
                     struct iovec *iov, int iovcnt,
                     unsigned nbytes)
{
        struct my_writer_state *state = (struct my_writer_state *) data;
        return FSTRM_RES_SUCCESS;
}

fstrm_res
my_writer_write_control(void *data,
                        struct iovec *iov, int iovcnt,
                        unsigned nbytes)
{
        struct my_writer_state *state = (struct my_writer_state *) data;
        return FSTRM_RES_SUCCESS;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \see fstrm_file_writer
 * \see fstrm_unix_writer
 *
 * @{
 */

/**
 * `create` method function type. This method is used to instantiate any
 * per-output state and process any per-output configuration options needed by
 * an `fstrm_writer` implementation.
 *
 * The interface for the `create` method allows user-specified,
 * implementation-defined options to be passed through the `wopt` parameter.
 * Note that the `create` method should **copy** any options provided via the
 * `wopt` parameter, so that the caller may fully dispose of any dynamic
 * allocations used for writer options after a call to fstrm_io_init().
 *
 * \see fstrm_writer_set_create()
 *
 * \param fio
 *      `fstrm_io` object.
 * \param wopt
 *      The `writer_options` parameter that was originally passed to
 *      fstrm_io_options_set_writer(). This is an opaque pointer and its
 *      contents are determined by the `fstrm_writer` implementation.
 * \param[out] data
 *      The `fstrm_writer` implementation may store a pointer containing state
 *      specific to the instantiation of the output here. For example, an
 *      `fstrm_writer` implementation whose outputs are backed by file
 *      descriptors might allocate a structure containing a file descriptor
 *      number and other resources and return the pointer to that state
 *      structure via this parameter. The value returned via this parameter will
 *      be provided to the other `fstrm_writer` methods taking a `data`
 *      parameter.
 *
 * \return
 *      #FSTRM_RES_SUCCESS on success, or any other #fstrm_res value on failure.
 */
typedef fstrm_res (*fstrm_writer_create_func)(
	struct fstrm_io *fio,
	const struct fstrm_writer_options *wopt,
	void **data);

/**
 * `destroy` method function type. This method is used to deallocate any
 * per-output resources used by an `fstrm_writer` implementation.
 *
 * \see fstrm_writer_set_destroy()
 *
 * \param data
 *      The `data` value returned by the `create` method.
 *
 * \return
 *      #FSTRM_RES_SUCCESS on success, or any other #fstrm_res value on failure.
 */
typedef fstrm_res (*fstrm_writer_destroy_func)(void *data);

/**
 * `open` method function type. This method is used to open the output used by
 * an `fstrm_writer` implementation and prepare it for writing. For example, if
 * an `fstrm_writer` implementation is backed by file I/O, this method might be
 * responsible for opening a file descriptor.
 *
 * This method may be called multiple times for the same object returned by the
 * `create` method. For instance, if a write to the output fails, the output
 * will have its `close` method called, and after the `reconnect_interval`
 * expires the I/O thread will attempt to reopen the output.
 *
 * \see fstrm_writer_set_open()
 * \see fstrm_io_options_set_reconnect_interval()
 *
 * \param data
 *      The `data` value returned by the `create` method.
 *
 * \return
 *      #FSTRM_RES_SUCCESS on success, or any other #fstrm_res value on failure.
 */
typedef fstrm_res (*fstrm_writer_open_func)(void *data);

/**
 * `close` method function type. This method is used to close the output used by
 * an `fstrm_writer` implementation. For example, if an `fstrm_writer`
 * implementation is backed by file I/O, this method might be responsible for
 * closing a file descriptor.
 *
 * This method will be called by the I/O thread subsequent to a failure of the
 * `write` or `write_control` methods.
 *
 * \see fstrm_writer_set_close()
 *
 * \param data
 *      The `data` value returned by the `create` method.
 *
 * \return
 *      #FSTRM_RES_SUCCESS on success, or any other #fstrm_res value on failure.
 */
typedef fstrm_res (*fstrm_writer_close_func)(void *data);

/**
 * `write_data` and `write_control` method function type. These methods are used
 * to write Frame Streams data frames and control frames respectively. If these
 * methods fail when called by the I/O thread, the `close` method will be
 * subsequently invoked.
 *
 * \param data
 *      The `data` value returned by the `create` method.
 * \param iov
 *      Pointer to the first element of the `iovec` array.
 * \param iovcnt
 *      Number of elements in the `iovec` array.
 * \param nbytes
 *      Total number of bytes described by the `iovec` array.
 *
 * \return
 *      #FSTRM_RES_SUCCESS on success, or any other #fstrm_res value on failure.
 */
typedef fstrm_res (*fstrm_writer_write_func)(
        void *data,
        struct iovec *iov,
        int iovcnt,
        unsigned nbytes);

/**
 * Initialize an `fstrm_writer` implementation. This object is used to define
 * the methods of a concrete `fstrm_writer` implementation. Once all the methods
 * have been set, this object becomes suitable for use as the `writer` parameter
 * to fstrm_io_options_set_writer().
 *
 * Once the methods for a concrete `fstrm_writer` implementation have been set
 * and used to instantiate outputs via a call to fstrm_io_init(), they should
 * *not* be overridden again by subsequent calls to the `fstrm_writer_set_*()`
 * functions.
 *
 * \see fstrm_writer_set_create()
 * \see fstrm_writer_set_destroy()
 * \see fstrm_writer_set_open()
 * \see fstrm_writer_set_close()
 * \see fstrm_writer_set_write_control()
 * \see fstrm_writer_set_write_data()
 * \see fstrm_io_options_set_writer()
 *
 * \return
 *      `fstrm_writer` object.
 */
struct fstrm_writer *
fstrm_writer_init(void);

/**
 * Destroy an `fstrm_writer` object.
 *
 * \param writer
 *      Pointer to an `fstrm_writer` object.
 */
void
fstrm_writer_destroy(struct fstrm_writer **writer);

/**
 * Set the `create` method for an `fstrm_writer` implementation.
 * \see fstrm_writer_create_func
 * \param writer
 *      `fstrm_writer` object.
 * \param w_create
 *      Function to use as the `fstrm_writer` `create` method.
 */
void
fstrm_writer_set_create(
	struct fstrm_writer *writer,
	fstrm_writer_create_func w_create);

/**
 * Set the `destroy` method for an `fstrm_writer` implementation.
 * \see fstrm_writer_destroy_func
 * \param writer
 *      `fstrm_writer` object.
 * \param w_destroy
 *      Function to use as the `fstrm_writer` `destroy` method.
 */
void
fstrm_writer_set_destroy(
	struct fstrm_writer *writer,
	fstrm_writer_destroy_func w_destroy);

/**
 * Set the `open` method for an `fstrm_writer` implementation.
 * \see fstrm_writer_open_func
 * \param writer
 *      `fstrm_writer` object.
 * \param w_open
 *      Function to use as the `fstrm_writer` `open` method.
 */
void
fstrm_writer_set_open(
	struct fstrm_writer *writer,
	fstrm_writer_open_func w_open);

/**
 * Set the `close` method for an `fstrm_writer` implementation.
 * \see fstrm_writer_close_func
 * \param writer
 *      `fstrm_writer` object.
 * \param w_close
 *      Function to use as the `fstrm_writer` `close` method.
 */
void
fstrm_writer_set_close(
	struct fstrm_writer *writer,
	fstrm_writer_close_func w_close);

/**
 * Set the `write_control` method for an `fstrm_writer` implementation.
 * \see fstrm_writer_write_func
 * \param writer
 *      `fstrm_writer` object.
 * \param w_write_control
 *      Function to use as the `fstrm_writer` `write_control` method.
 */
void
fstrm_writer_set_write_control(
	struct fstrm_writer *writer,
	fstrm_writer_write_func w_write_control);

/**
 * Set the `write_data` method for an `fstrm_writer` implementation.
 * \see fstrm_writer_write_func
 * \param writer
 *      `fstrm_writer` object.
 * \param w_write_data
 *      Function to use as the `fstrm_writer` `write_data` method.
 */
void
fstrm_writer_set_write_data(
	struct fstrm_writer *writer,
	fstrm_writer_write_func w_write_data);

/**@}*/

/*!
 * \defgroup fstrm_file_writer fstrm_file_writer
 *
 * `fstrm_file_writer` is a concrete implementation of the `fstrm_writer`
 * interface. It writes Frame Streams content into the regular file specified by
 * fstrm_file_writer_options_set_file_path. Note that the opened file will be
 * truncated.
 *
 * The `fstrm_file_writer` implementation is generally used with \ref fstrm_io
 * by creating an `fstrm_file_writer_options` object, setting the `file_path`
 * parameter on this options object, and passing it to
 * fstrm_io_options_set_writer(), as in the following example:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        const char *file_path = "/path/to/output.fs";

        struct fstrm_file_writer_options *fwopt;
        fwopt = fstrm_file_writer_options_init();
        fstrm_file_writer_options_set_file_path(fwopt, file_path);

        struct fstrm_io_options *fopt;
        fopt = fstrm_io_options_init();
        fstrm_io_options_set_writer(fopt, fstrm_file_writer, fwopt);

        char *errstr = NULL;
        struct fstrm_io *fio;
        fio = fstrm_io_init(fopt, &errstr);
        fstrm_io_options_destroy(&fopt);
        fstrm_file_writer_options_destroy(&fwopt);
        if (fio != NULL) {
                // fio is ready to accept data now.
        } else {
                fprintf(stderr, "Error: fstrm_io_init() failed: %s\n", errstr);
                free(errstr);
        }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * @{
 */


/**
 * An `fstrm_writer` implementation that writes Frame Streams content to a
 * regular file. This value may be passed as the `writer` parameter to
 * fstrm_io_options_set_writer().
 */
extern const struct fstrm_writer *fstrm_file_writer;

/**
 * Initialize an `fstrm_file_writer_options` object, which is needed to
 * configure `fstrm_file_writer`.
 *
 * \return
 *      `fstrm_file_writer_options` object.
 */
struct fstrm_file_writer_options *
fstrm_file_writer_options_init(void);

/**
 * Destroy an `fstrm_file_writer_options` object.
 *
 * \param fwopt
 *      Pointer to `fstrm_file_writer_options` object.
 */
void
fstrm_file_writer_options_destroy(
	struct fstrm_file_writer_options **fwopt);

/**
 * Set the `file_path` option. This is the filesystem path that Frame Streams
 * content will be written to. Note that if this path already exists, it will be
 * overwritten.
 *
 * \param fwopt
 *      `fstrm_file_writer_options` object.
 * \param file_path
 *      The filesystem path.
 */
void
fstrm_file_writer_options_set_file_path(
	struct fstrm_file_writer_options *fwopt,
	const char *file_path);

/**@}*/

/*!
 * \defgroup fstrm_unix_writer fstrm_unix_writer
 *
 * `fstrm_unix_writer` is a concrete implementation of the `fstrm_writer`
 * interface. It connects to the `AF_UNIX` domain socket specified by
 * fstrm_unix_writer_options_set_socket_path() and writes Frame Streams content
 * to this socket. Note that the socket type used will be `SOCK_STREAM`.
 *
 * Note that the `AF_UNIX` socket does not have to exist at connection time.
 * `fstrm_io` will periodically attempt to reconnect a disconnected socket.
 *
 * \see fstrm_io_options_set_reconnect_interval()
 *
 * The `fstrm_unix_writer` implementation is generally used with \ref fstrm_io
 * by creating an `fstrm_unix_writer_options` object, setting the `socket_path`
 * parameter on this options object, and passing it to
 * fstrm_io_options_set_writer(), as in the following example:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        const char *socket_path = "/path/to/unix.sock";

        struct fstrm_unix_writer_options *uwopt;
        uwopt = fstrm_unix_writer_options_init();
        fstrm_unix_writer_options_set_socket_path(uwopt, socket_path);

        struct fstrm_io_options *fopt;
        fopt = fstrm_io_options_init();
        fstrm_io_options_set_writer(fopt, fstrm_unix_writer, uwopt);

        char *errstr = NULL;
        struct fstrm_io *fio;
        fio = fstrm_io_init(fopt, &errstr);
        fstrm_io_options_destroy(&fopt);
        fstrm_unix_writer_options_destroy(&uwopt);
        if (fio != NULL) {
                // fio is ready to accept data now.
        } else {
                fprintf(stderr, "Error: fstrm_io_init() failed: %s\n", errstr);
                free(errstr);
        }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * @{
 */

/**
 * An `fstrm_writer` implementation that writes Frame Streams content to an
 * `AF_UNIX` domain socket. This value may be passed as the `writer` parameter
 * to fstrm_io_options_set_writer().
 */
extern const struct fstrm_writer *fstrm_unix_writer;

/**
 * Initialize an `fstrm_unix_writer_options` object, which is needed to
 * configure `fstrm_unix_writer`.
 *
 * \return
 *      `fstrm_unix_writer_options` object.
 */
struct fstrm_unix_writer_options *
fstrm_unix_writer_options_init(void);

/**
 * Destroy an `fstrm_unix_writer_options` object.
 *
 * \param fuwopt
 *      Pointer to `fstrm_unix_writer_options` object.
 */
void
fstrm_unix_writer_options_destroy(
	struct fstrm_unix_writer_options **fuwopt);

/**
 * Set the `socket_path` option. This is the filesystem path to connect the
 * `AF_UNIX` socket to. This option is required for `fstrm_unix_writer` objects.
 *
 * \param fuwopt
 *      `fstrm_unix_writer_options` object.
 * \param socket_path
 *      The filesystem path for the `AF_UNIX` domain socket.
 */
void
fstrm_unix_writer_options_set_socket_path(
	struct fstrm_unix_writer_options *fuwopt,
	const char *socket_path);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* FSTRM_H */

