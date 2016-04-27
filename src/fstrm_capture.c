/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <fstrm.h>

#include "libmy/argv.h"
#include "libmy/my_alloc.h"
#include "libmy/print_string.h"

#if HAVE_DECL_FFLUSH_UNLOCKED
# define fflush fflush_unlocked
#endif

#if HAVE_DECL_FREAD_UNLOCKED
# define fread fread_unlocked
#endif

#if HAVE_DECL_FWRITE_UNLOCKED
# define fwrite fwrite_unlocked
#endif

#define CAPTURE_HIGH_WATERMARK	262144

struct capture;
struct capture_args;
struct conn;

typedef enum {
	CONN_STATE_READING_CONTROL_READY,
	CONN_STATE_READING_CONTROL_START,
	CONN_STATE_READING_DATA,
	CONN_STATE_STOPPED,
} conn_state;

typedef enum conn_verbosity {
	CONN_CRITICAL		= 0,
	CONN_ERROR		= 1,
	CONN_WARNING		= 2,
	CONN_INFO		= 3,
	CONN_DEBUG		= 4,
	CONN_TRACE		= 5,
} conn_verbosity;

struct conn {
	struct capture		*ctx;
	conn_state		state;
	uint32_t		len_frame_payload;
	uint32_t		len_frame_total;
	size_t			len_buf;
	size_t			bytes_read;
	size_t			count_read;
	struct bufferevent	*bev;
	struct evbuffer		*ev_input;
	struct evbuffer		*ev_output;
	struct fstrm_control	*control;
};

struct capture {
	struct capture_args	*args;

	struct sockaddr_un	sa;
	evutil_socket_t		listen_fd;
	struct event_base	*ev_base;
	struct evconnlistener	*ev_connlistener;
	struct event		*ev_sighup;

	FILE			*output_file;
	char			*output_fname;
	time_t			output_open_timestamp;

	size_t			bytes_written;
	size_t			count_written;

	struct tm *(*calendar_fn)(const time_t *, struct tm *);
};

struct capture_args {
	bool			help;
	int			debug;
	bool			localtime;
	bool			gmtime;
	char			*str_content_type;
	char			*str_read_unix;
	char			*str_write_fname;
	int			split_seconds;
};

static struct capture		g_program_ctx;
static struct capture_args	g_program_args;

static argv_t g_args[] = {
	{ 'h',	"help",
		ARGV_BOOL,
		&g_program_args.help,
		NULL,
		"display this help text and exit" },

	{ 'd',	"debug",
		ARGV_INCR,
		&g_program_args.debug,
		NULL,
		"increment debugging level" },

	{ 't',	"type",
		ARGV_CHAR_P,
		&g_program_args.str_content_type,
		"<STRING>",
		"Frame Streams content type" },

	{ 'u',	"unix",
		ARGV_CHAR_P,
		&g_program_args.str_read_unix,
		"<FILENAME>",
		"Unix socket path to read from" },

	{ 'w',	"write",
		ARGV_CHAR_P,
		&g_program_args.str_write_fname,
		"<FILENAME>",
		"file path to write Frame Streams data to" },

	{ 's',	"split",
		ARGV_INT,
		&g_program_args.split_seconds,
		"<SECONDS>",
		"seconds before rotating output file" },

	{ '\0',	"localtime",
		ARGV_BOOL,
		&g_program_args.localtime,
		NULL,
		"filter -w path with strftime (local time)" },

	{ '\0',	"gmtime",
		ARGV_BOOL,
		&g_program_args.gmtime,
		NULL,
		"filter -w path with strftime (UTC)" },

	{ ARGV_LAST },
};

static struct conn *
conn_init(struct capture *ctx)
{
	struct conn *conn;
	conn = my_calloc(1, sizeof(*conn));
	conn->ctx = ctx;
	conn->state = CONN_STATE_READING_CONTROL_READY;
	conn->control = fstrm_control_init();
	return conn;
}

static void
conn_destroy(struct conn **conn)
{
	if (*conn != NULL) {
		fstrm_control_destroy(&(*conn)->control);
		my_free(*conn);
	}
}

static void
conn_log(int level, struct conn *conn, const char *format, ...)
{
	if (level > conn->ctx->args->debug)
		return;
	int fd = -1;

	if (conn->bev != NULL)
		fd = (int) bufferevent_getfd(conn->bev);

	fprintf(stderr, "%s: connection fd %d: ", argv_program, fd);

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fputc('\n', stderr);
}

static void
conn_log_data(int level, struct conn *conn, const void *data, size_t len, const char *format, ...)
{
	if (level > conn->ctx->args->debug)
		return;
	fprintf(stderr, "%s: connection fd %d: ", argv_program,
		(int) bufferevent_getfd(conn->bev));

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	print_string(data, len, stderr);
	fputc('\n', stderr);
}

static void
cb_close_conn(struct bufferevent *bev, short error, void *arg)
{
	struct conn *conn = (struct conn *) arg;

	if (error & BEV_EVENT_ERROR)
		conn_log(CONN_CRITICAL, conn, "libevent error: %s (%d)",
			 strerror(errno), errno);

	conn_log(CONN_INFO, conn, "closing (read %zd frames, %zd bytes)",
		 conn->count_read, conn->bytes_read);

	/*
	 * The BEV_OPT_CLOSE_ON_FREE flag is set on our bufferevent's, so the
	 * following call to bufferevent_free() will close the underlying
	 * socket transport.
	 */
	bufferevent_free(bev);
	conn_destroy(&conn);
}

static bool
usage(const char *msg)
{
	if (msg)
		fprintf(stderr, "%s: Usage error: %s\n", argv_program, msg);
	argv_usage(g_args, ARGV_USAGE_DEFAULT);
	argv_cleanup(g_args);
	exit(EXIT_FAILURE);
}

static bool
parse_args(const int argc, char **argv, struct capture *ctx)
{
	argv_version_string = PACKAGE_VERSION;

	if (argv_process(g_args, argc, argv) != 0)
		return false;

	/* Validate args. */
	if (g_program_args.help)
		return false;
	if (g_program_args.str_content_type == NULL)
		usage("Frame Streams content type (--type) is not set");
	if (g_program_args.str_read_unix == NULL)
		usage("Unix socket path to read from (--unix) is not set");
	if (g_program_args.str_write_fname == NULL)
		usage("File path to write Frame Streams data to (--write) is not set");
	if (strcmp(g_program_args.str_write_fname, "-") == 0) {
		if (isatty(STDOUT_FILENO) == 1)
			usage("Refusing to write binary output to a terminal");
		if (g_program_args.split_seconds != 0)
			usage("Cannot use output splitting when writing to stdout");
	}
	if (g_program_args.localtime && g_program_args.gmtime)
		usage("--localtime and --gmtime are mutually exclusive");
	if (g_program_args.split_seconds && !g_program_args.localtime && !g_program_args.gmtime)
		usage("--split requires either --localtime or --gmtime");

	/* Set calendar function, if needed. */
	if (g_program_args.localtime)
		ctx->calendar_fn = localtime_r;
	else if (g_program_args.gmtime)
		ctx->calendar_fn = gmtime_r;

	return true;
}

static bool
open_read_unix(struct capture *ctx)
{
	int ret;

	/* Construct sockaddr_un structure. */
	if (strlen(ctx->args->str_read_unix) + 1 >
	    sizeof(ctx->sa.sun_path))
	{
		usage("Unix socket path is too long");
		return false;
	}
	ctx->sa.sun_family = AF_UNIX;
	strncpy(ctx->sa.sun_path,
		ctx->args->str_read_unix,
		sizeof(ctx->sa.sun_path) - 1);

	/* Remove a previously bound socket existing on the filesystem. */
	ret = remove(ctx->sa.sun_path);
	if (ret != 0 && errno != ENOENT) {
		fprintf(stderr, "%s: failed to remove existing socket path %s\n",
			argv_program, ctx->sa.sun_path);
		return false;
	}

	/* Success. */
	fprintf(stderr, "%s: listening on socket path %s\n",
		argv_program, ctx->sa.sun_path);
	return true;
}

static bool
close_write_stop(struct capture *ctx)
{
	fstrm_res res;
	uint8_t control_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_control_frame = sizeof(control_frame);
	struct fstrm_control *c = NULL;

	/* Initialize the STOP control frame. */
	c = fstrm_control_init();
	res = fstrm_control_set_type(c, FSTRM_CONTROL_STOP);
	if (res != fstrm_res_success)
		goto fail;

	/* Encode the STOP frame. */
	res = fstrm_control_encode(c, control_frame, &len_control_frame,
		FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success)
		goto fail;

	/* Write the STOP frame. */
	size_t n_written;
	n_written = fwrite(control_frame, len_control_frame, 1, ctx->output_file);
	if (n_written != 1)
		goto fail;

	/* Success. */
	ctx->bytes_written += len_control_frame;
	ctx->count_written += 1;
	fstrm_control_destroy(&c);
	return true;

fail:
	fstrm_control_destroy(&c);
	return false;
}

static bool
open_write_start(struct capture *ctx)
{
	fstrm_res res;
	uint8_t control_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_control_frame = sizeof(control_frame);
	struct fstrm_control *c = NULL;

	/* Initialize the START control frame. */
	c = fstrm_control_init();
	res = fstrm_control_set_type(c, FSTRM_CONTROL_START);
	if (res != fstrm_res_success)
		goto fail;

	/* Set the "Content Type". */
	res = fstrm_control_add_field_content_type(c,
		(const uint8_t *) ctx->args->str_content_type,
		strlen(ctx->args->str_content_type));
	if (res != fstrm_res_success)
		goto fail;

	/* Encode the START frame. */
	res = fstrm_control_encode(c, control_frame, &len_control_frame,
		FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success)
		goto fail;

	/* Write the START frame. */
	size_t n_written;
	n_written = fwrite(control_frame, len_control_frame, 1, ctx->output_file);
	if (n_written != 1)
		goto fail;
	(void) fflush(ctx->output_file);

	/* Success. */
	ctx->bytes_written += len_control_frame;
	ctx->count_written += 1;
	fstrm_control_destroy(&c);
	return true;

fail:
	fstrm_control_destroy(&c);
	return false;
}

static const char *
update_output_fname(struct capture *ctx)
{
	time_t time_now = {0};
	struct tm tm_now = {0};

	/* Get current broken-down time representation. */
	tzset();
	time_now = time(NULL);
	ctx->calendar_fn(&time_now, &tm_now);

	/* Save current time. */
	ctx->output_open_timestamp = time_now;

	/*
	 * Filter ctx->args->str_write_fname with strftime(), store output in
	 * ctx->output_fname. Assume strftime() lengthens the string by no more
	 * than 256 bytes.
	 */
	if (ctx->output_fname != NULL)
		my_free(ctx->output_fname);
	const size_t len_output_fname = strlen(ctx->args->str_write_fname) + 256;
	ctx->output_fname = my_calloc(1, len_output_fname);

	if (strftime(ctx->output_fname, len_output_fname,
		     ctx->args->str_write_fname, &tm_now) <= 0)
	{
		my_free(ctx->output_fname);
		fprintf(stderr, "%s: strftime() failed on format string \"%s\"\n",
			argv_program, ctx->args->str_write_fname);
		return NULL;
	}

	return ctx->output_fname;
}

static bool
open_write_file(struct capture *ctx)
{
	const char *fname = ctx->args->str_write_fname;

	if (strcmp(fname, "-") == 0) {
		/* Use already opened FILE* for stdout. */
		ctx->output_file = stdout;
	} else {
		mode_t open_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
		int open_flags = O_CREAT | O_WRONLY | O_TRUNC;
#if defined(O_CLOEXEC)
		open_flags |= O_CLOEXEC;
#endif

		/* Rewrite the output filename if needed. */
		if (ctx->calendar_fn) {
			fname = update_output_fname(ctx);
			if (fname == NULL)
				return false;
		}

		/* Open the file descriptor. */
		int fd = open(fname, open_flags, open_mode);
		if (fd == -1) {
			fprintf(stderr, "%s: failed to open output file %s\n",
				argv_program, fname);
			return false;
		}

		/* Open the FILE object. */
		ctx->output_file = fdopen(fd, "w");
		if (!ctx->output_file) {
			close(fd);
			fprintf(stderr, "%s: failed to fdopen output file %s\n",
				argv_program, fname);
			return false;
		}
	}

	/* Reset output statistics. */
	ctx->count_written = 0;
	ctx->bytes_written = 0;

	/* Write the START frame. */
	if (!open_write_start(ctx)) {
		fclose(ctx->output_file);
		ctx->output_file = NULL;
		fprintf(stderr, "%s: failed to write output file %s\n",
			argv_program, fname);
		return false;
	}

	/* Success. */
	fprintf(stderr, "%s: opened output file %s\n", argv_program, fname);
	return true;
}

static bool
close_write_file(struct capture *ctx)
{
	if (ctx->output_file != NULL) {
		/* Write the STOP frame. */
		if (!close_write_stop(ctx))
			return false;

		/* Close the FILE object. */
		fclose(ctx->output_file);
		ctx->output_file = NULL;
	}

	/* Success. */
	fprintf(stderr, "%s: closed output file %s (wrote %zd frames, %zd bytes)\n",
		argv_program, ctx->output_fname ? : ctx->args->str_write_fname,
		ctx->count_written, ctx->bytes_written);
	return true;
}

static void
process_data_frame(struct conn *conn)
{
	conn_log(CONN_TRACE, conn, "processing data frame (%u bytes)",
		 conn->len_frame_total);

	/*
	 * Peek at 'conn->len_frame_total' bytes of data from the evbuffer, and
	 * write them to the output file.
	 */

	/* Determine how many iovec's we need to read. */
	const int n_vecs = evbuffer_peek(conn->ev_input, conn->len_frame_total, NULL, NULL, 0);

	/* Allocate space for the iovec's. */
	struct evbuffer_iovec vecs[n_vecs];

	/* Retrieve the iovec's. */
	const int n = evbuffer_peek(conn->ev_input, conn->len_frame_total, NULL, vecs, n_vecs);
	assert(n == n_vecs);

	/* Write each iovec to the output file. */
	size_t bytes_read = 0;
	for (int i = 0; i < n_vecs; i++) {
		size_t len = vecs[i].iov_len;

		/* Only read up to 'conn->len_frame_total' bytes. */
		if (bytes_read + len > conn->len_frame_total)
			len = conn->len_frame_total - bytes_read;

		/* Do the fwrite(). Fail hard if it fails. */
		size_t res = fwrite(vecs[i].iov_base, len, 1, conn->ctx->output_file);
		if (res != 1) {
			fprintf(stderr, "%s: fwrite() failed: %s\n",
				argv_program, strerror(errno));
			exit(EXIT_FAILURE);
		}
		bytes_read += len;
	}

	/* Check that exactly the right number of bytes were written. */
	assert(bytes_read == conn->len_frame_total);

	/* Delete the data frame from the input buffer. */
	evbuffer_drain(conn->ev_input, conn->len_frame_total);

	/* Accounting. */
	conn->count_read += 1;
	conn->bytes_read += bytes_read;
	conn->ctx->count_written += 1;
	conn->ctx->bytes_written += bytes_read;
}

static void
maybe_rotate_output(struct conn *conn)
{
	/* Output file rotation requested? */
	if (conn->ctx->args->split_seconds > 0) {
		time_t t_now = time(NULL);

		/* Is it time to rotate? */
		if (t_now >= conn->ctx->output_open_timestamp + conn->ctx->args->split_seconds) {
			/* Rotate output file, fail hard if unsuccessful. */
			if (!close_write_file(conn->ctx)) {
				fprintf(stderr, "%s: %s: close_write_file() failed\n",
					argv_program, __func__);
				exit(EXIT_FAILURE);
			}
			if (!open_write_file(conn->ctx)) {
				fprintf(stderr, "%s: %s: open_write_file() failed\n",
					argv_program, __func__);
				exit(EXIT_FAILURE);
			}
		}
	}
}

static bool
send_frame(struct conn *conn, const void *data, size_t size)
{
	conn_log_data(CONN_TRACE, conn, data, size, "writing frame (%zd) bytes: ", size);

	if (bufferevent_write(conn->bev, data, size) != 0) {
		conn_log(CONN_WARNING, conn, "bufferevent_write() failed");
		return false;
	}

	return true;
}

static bool
match_content_type(struct conn *conn)
{
	fstrm_res res;

	/* Match the "Content Type" against ours. */
	res = fstrm_control_match_field_content_type(conn->control,
		(const uint8_t *) conn->ctx->args->str_content_type,
		strlen(conn->ctx->args->str_content_type));
	if (res != fstrm_res_success) {
		conn_log(CONN_WARNING, conn, "no CONTENT_TYPE matching: \"%s\"",
			 conn->ctx->args->str_content_type);
		return false;
	}

	/* Success. */
	return true;
}

static bool
write_control_frame(struct conn *conn)
{
	fstrm_res res;
	uint8_t control_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_control_frame = sizeof(control_frame);

	/* Encode the control frame. */
	res = fstrm_control_encode(conn->control,
		control_frame, &len_control_frame,
		FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success)
		return false;

	/* Send the control frame. */
	fstrm_control_type type = 0;
	(void)fstrm_control_get_type(conn->control, &type);
	conn_log(CONN_DEBUG, conn, "sending %s (%d)",
		fstrm_control_type_to_str(type), type);
	if (!send_frame(conn, control_frame, len_control_frame))
		return false;

	/* Success. */
	return true;
}

static bool
process_control_frame_ready(struct conn *conn)
{
	fstrm_res res;

	const uint8_t *content_type = NULL;
	size_t len_content_type = 0;
	size_t n_content_type = 0;

	/* Retrieve the number of "Content Type" fields. */
	res = fstrm_control_get_num_field_content_type(conn->control, &n_content_type);
	if (res != fstrm_res_success)
		return false;

	for (size_t i = 0; i < n_content_type; i++) {
		res = fstrm_control_get_field_content_type(conn->control, i,
							   &content_type,
							   &len_content_type);
		if (res != fstrm_res_success)
			return false;
		conn_log_data(CONN_TRACE, conn,
			      content_type, len_content_type,
			      "CONTENT_TYPE [%zd/%zd] (%zd bytes): ",
			      i + 1, n_content_type, len_content_type);
	}

	/* Match the "Content Type" against ours. */
	if (!match_content_type(conn))
		return false;

	/* Setup the ACCEPT frame. */
	fstrm_control_reset(conn->control);
	res = fstrm_control_set_type(conn->control, FSTRM_CONTROL_ACCEPT);
	if (res != fstrm_res_success)
		return false;
	res = fstrm_control_add_field_content_type(conn->control,
		(const uint8_t *) conn->ctx->args->str_content_type,
		strlen(conn->ctx->args->str_content_type));
	if (res != fstrm_res_success)
		return false;
	
	/* Send the ACCEPT frame. */
	if (!write_control_frame(conn))
		return false;

	/* Success. */
	conn->state = CONN_STATE_READING_CONTROL_START;
	return true;
}

static bool
process_control_frame_start(struct conn *conn)
{
	/* Match the "Content Type" against ours. */
	if (!match_content_type(conn))
		return false;
	
	/* Success. */
	conn->state = CONN_STATE_READING_DATA;
	return true;
}

static bool
process_control_frame_stop(struct conn *conn)
{
	fstrm_res res;

	conn->state = CONN_STATE_STOPPED;

	/* Setup the FINISH frame. */
	fstrm_control_reset(conn->control);
	res = fstrm_control_set_type(conn->control, FSTRM_CONTROL_FINISH);
	if (res != fstrm_res_success)
		return false;

	/* Send the FINISH frame. */
	if (!write_control_frame(conn))
		return false;
	
	/* Success, though we return false in order to shut down the connection. */
	return false;
}

static bool
process_control_frame(struct conn *conn)
{
	fstrm_res res;
	fstrm_control_type type;

	/* Get the control frame type. */
	res = fstrm_control_get_type(conn->control, &type);
	if (res != fstrm_res_success)
		return false;
	conn_log(CONN_DEBUG, conn, "received %s (%u)",
		 fstrm_control_type_to_str(type), type);

	switch (conn->state) {
	case CONN_STATE_READING_CONTROL_READY: {
		if (type != FSTRM_CONTROL_READY)
			return false;
		return process_control_frame_ready(conn);
	}
	case CONN_STATE_READING_CONTROL_START: {
		if (type != FSTRM_CONTROL_START)
			return false;
		return process_control_frame_start(conn);
	}
	case CONN_STATE_READING_DATA: {
		if (type != FSTRM_CONTROL_STOP)
			return false;
		return process_control_frame_stop(conn);
	}
	default:
		return false;
	}

	/* Success. */
	return true;
}

static bool
load_control_frame(struct conn *conn)
{
	fstrm_res res;
	uint8_t *control_frame = NULL;

	/* Check if the frame is too big. */
	if (conn->len_frame_total >= FSTRM_CONTROL_FRAME_LENGTH_MAX) {
		/* Malformed. */
		return false;
	}

	/* Get a pointer to the full, linearized control frame. */
	control_frame = evbuffer_pullup(conn->ev_input, conn->len_frame_total);
	if (!control_frame) {
		/* Malformed. */
		return false;
	}
	conn_log_data(CONN_TRACE, conn, control_frame, conn->len_frame_total,
		      "reading control frame (%u bytes): ", conn->len_frame_total);

	/* Decode the control frame. */
	res = fstrm_control_decode(conn->control,
				   control_frame,
				   conn->len_frame_total,
				   FSTRM_CONTROL_FLAG_WITH_HEADER);
	if (res != fstrm_res_success) {
		/* Malformed. */
		return false;
	}

	/* Drain the data read. */
	evbuffer_drain(conn->ev_input, conn->len_frame_total);

	/* Success. */
	return true;
}

static bool
can_read_full_frame(struct conn *conn)
{
	uint32_t tmp[2] = {0};

	/*
	 * This tracks the total number of bytes that must be removed from the
	 * input buffer to read the entire frame. */
	conn->len_frame_total = 0;

	/* Check if the frame length field has fully arrived. */
	if (conn->len_buf < sizeof(uint32_t))
		return false;

	/* Read the frame length field. */
	evbuffer_copyout(conn->ev_input, &tmp[0], sizeof(uint32_t));
	conn->len_frame_payload = ntohl(tmp[0]);

	/* Account for the frame length field. */
	conn->len_frame_total += sizeof(uint32_t);

	/* Account for the length of the frame payload. */
	conn->len_frame_total += conn->len_frame_payload;

	/* Check if this is a control frame. */
	if (conn->len_frame_payload == 0) {
		uint32_t len_control_frame = 0;

		/*
		 * Check if the control frame length field has fully arrived.
		 * Note that the input buffer hasn't been drained, so we also
		 * need to account for the initial frame length field. That is,
		 * there must be at least 8 bytes available in the buffer.
		 */
		if (conn->len_buf < 2*sizeof(uint32_t))
			return false;

		/* Read the control frame length. */
		evbuffer_copyout(conn->ev_input, &tmp[0], 2*sizeof(uint32_t));
		len_control_frame = ntohl(tmp[1]);

		/* Account for the length of the control frame length field. */
		conn->len_frame_total += sizeof(uint32_t);

		/* Enforce minimum and maximum control frame size. */
		if (len_control_frame < sizeof(uint32_t) ||
		    len_control_frame > FSTRM_CONTROL_FRAME_LENGTH_MAX)
		{
			cb_close_conn(conn->bev, 0, conn);
			return false;
		}

		/* Account for the control frame length. */
		conn->len_frame_total += len_control_frame;
	}

	/*
	 * Check if the frame has fully arrived. 'len_buf' must have at least
	 * the number of bytes needed in order to read the full frame, which is
	 * exactly 'len_frame_total'.
	 */
	if (conn->len_buf < conn->len_frame_total) {
		conn_log(CONN_TRACE, conn, "incomplete message (have %zd bytes, want %u)",
			 conn->len_buf, conn->len_frame_total);
		return false;
	}

	/* Success. The entire frame can now be read from the buffer. */
	return true;
}

static void
cb_read(struct bufferevent *bev, void *arg)
{
	struct conn *conn = (struct conn *) arg;
	conn->bev = bev;
	conn->ev_input = bufferevent_get_input(conn->bev);
	conn->ev_output = bufferevent_get_output(conn->bev);

	for (;;) {
		/* Get the number of bytes available in the buffer. */
		conn->len_buf = evbuffer_get_length(conn->ev_input);

		/* Check if there is any data available in the buffer. */
		if (conn->len_buf <= 0)
			return;

		/* Check if the full frame has arrived. */
		if (!can_read_full_frame(conn))
			return;

		/* Process the frame. */
		if (conn->len_frame_payload > 0) {
			/* This is a data frame. */
			process_data_frame(conn);

			/* Check if it's time to rotate the output file. */
			maybe_rotate_output(conn);
		} else {
			/* This is a control frame. */
			if (!load_control_frame(conn)) {
				/* Malformed control frame, shut down the connection. */
				cb_close_conn(conn->bev, 0, conn);
				return;
			}

			if (!process_control_frame(conn)) {
				/*
				 * Invalid control state requested, or the
				 * end-of-stream has been reached. Shut down
				 * the connection.
				 */
				cb_close_conn(conn->bev, 0, conn);
				return;
			}
		}
	}
}

static void
cb_accept_conn(struct evconnlistener *listener, evutil_socket_t fd,
	       struct sockaddr *sa, int socklen, void *arg)
{
	struct capture *ctx = (struct capture *) arg;
	struct event_base *base = evconnlistener_get_base(listener);

	/* Set up a bufferevent and per-connection context for the new connection. */
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		if (ctx->args->debug >= CONN_ERROR)
			fprintf(stderr, "%s: bufferevent_socket_new() failed\n",
				argv_program);
		evutil_closesocket(fd);
		return;
	}
	struct conn *conn = conn_init(ctx);
	bufferevent_setcb(bev, cb_read, NULL, cb_close_conn, (void *) conn);
	bufferevent_setwatermark(bev, EV_READ, 0, CAPTURE_HIGH_WATERMARK);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	if (ctx->args->debug >= CONN_INFO)
		fprintf(stderr, "%s: accepted new connection fd %d\n", argv_program, fd);
}

static void
cb_accept_error(struct evconnlistener *listener, void *arg)
{
	const int err = EVUTIL_SOCKET_ERROR();
	fprintf(stderr, "%s: accept() failed: %s\n", argv_program,
		evutil_socket_error_to_string(err));
}

static void
do_sighup(evutil_socket_t sig, short events, void *user_data)
{
	struct capture *ctx = user_data;
	if (ctx->output_file) {
		fflush(ctx->output_file);
		fprintf(stderr, "%s: received SIGHUP, flushing output\n", argv_program);
	}
}

static bool
setup_event_loop(struct capture *ctx)
{
	/* Create the event base. */
	ctx->ev_base = event_base_new();
	if (!ctx->ev_base)
		return false;

	/* Create the evconnlistener. */
	unsigned flags = 0;
	flags |= LEV_OPT_CLOSE_ON_FREE; /* Closes underlying sockets. */
	flags |= LEV_OPT_CLOSE_ON_EXEC; /* Sets FD_CLOEXEC on underlying fd's. */
	flags |= LEV_OPT_REUSEABLE; /* Sets SO_REUSEADDR on listener. */
	ctx->ev_connlistener = evconnlistener_new_bind(ctx->ev_base,
		cb_accept_conn, (void *) ctx, flags, -1,
		(struct sockaddr *) &ctx->sa, sizeof(ctx->sa));
	if (!ctx->ev_connlistener) {
		event_base_free(ctx->ev_base);
		ctx->ev_base = NULL;
		return false;
	}
	evconnlistener_set_error_cb(ctx->ev_connlistener, cb_accept_error);

	/* Register our SIGHUP handler. */
	ctx->ev_sighup = evsignal_new(ctx->ev_base, SIGHUP, &do_sighup,
				      &g_program_ctx);
	evsignal_add(ctx->ev_sighup, NULL);

	/* Success. */
	return true;
}

static void
shutdown_handler(int signum __attribute__((unused)))
{
	event_base_loopexit(g_program_ctx.ev_base, NULL);
}

static bool
setup_signals(void)
{
	struct sigaction sa = {
		.sa_handler = shutdown_handler,
	};

	if (sigemptyset(&sa.sa_mask) != 0)
		return false;
	if (sigaction(SIGTERM, &sa, NULL) != 0)
		return false;
	if (sigaction(SIGINT, &sa, NULL) != 0)
		return false;

	/* Success. */
	return true;
}

static void
cleanup(struct capture *ctx)
{
	argv_cleanup(g_args);
	if (ctx->ev_sighup != NULL)
		event_free(ctx->ev_sighup);
	if (ctx->ev_connlistener != NULL)
		evconnlistener_free(ctx->ev_connlistener);
	if (ctx->ev_base != NULL)
		event_base_free(ctx->ev_base);
	my_free(ctx->output_fname);
}

int
main(int argc, char **argv)
{
	/* Parse arguments. */
	if (!parse_args(argc, argv, &g_program_ctx)) {
		usage(NULL);
		return EXIT_FAILURE;
	}
	g_program_ctx.args = &g_program_args;

	/* Open the Unix socket input. */
	if (!open_read_unix(&g_program_ctx))
		return EXIT_FAILURE;

	/* Open the file output. */
	if (!open_write_file(&g_program_ctx))
		return EXIT_FAILURE;

	/* Setup the event loop. */
	if (!setup_event_loop(&g_program_ctx)) {
		fprintf(stderr, "%s: failed to setup event loop\n", argv_program);
		return EXIT_FAILURE;
	}

	/* Setup signals. */
	if (!setup_signals()) {
		fprintf(stderr, "%s: failed to setup signals\n", argv_program);
		return EXIT_FAILURE;
	}

	/* Run the event loop. */
	if (event_base_dispatch(g_program_ctx.ev_base) != 0) {
		fprintf(stderr, "%s: failed to start event loop\n", argv_program);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "%s: shutting down\n", argv_program);

	/* Shut down. */
	if (!close_write_file(&g_program_ctx))
		return EXIT_FAILURE;
	cleanup(&g_program_ctx);

	/* Success. */
	return EXIT_SUCCESS;
}
