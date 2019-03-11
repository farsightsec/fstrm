/*
 * Copyright (c) 2018 by Farsight Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <fstrm.h>

#include "libmy/argv.h"

struct replay {
	struct replay_args 	*args;
	uint8_t 		*content_type;
	size_t			len_content_type;
};

struct replay_args {
	bool			help;
	char			*content_type;
	char			*unix_address;
	char			*tcp_address;
	char			*tcp_port;
	argv_array_t		files;
};

static struct replay		g_program_ctx;
static struct replay_args	g_program_args;

static argv_t g_args[] = {
	{ 'h',  "help",
		ARGV_BOOL,
		&g_program_args.help,
		NULL,
		"display this help text and exit" },

	{ 't',  "type",
		ARGV_CHAR_P | ARGV_FLAG_MAND,
		&g_program_args.content_type,
		"<STRING>",
		"Frame Streams content type" },

	{ 'u',  "unix",
		ARGV_CHAR_P,
		&g_program_args.unix_address,
		"<FILENAME>",
		"Unix socket path to write to" },

	/* ARGV_ONE_OF indicates that the user must specify the
	 * previous option (-u) or next option (-a), but not both.
	 */
	{ ARGV_ONE_OF, 0, 0, 0, 0, 0 },

	{ 'a',  "tcp",
		ARGV_CHAR_P,
		&g_program_args.tcp_address,
		"<ADDRESS>",
		"TCP socket address to write to" },

	{ 'p',  "port",
		ARGV_CHAR_P,
		&g_program_args.tcp_port,
		"<PORT>",
		"TCP socket port to write to" },

	{ 'r', "read-file",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY | ARGV_FLAG_MAND,
		&g_program_args.files,
		"<FILE>",
		"Files to read Frame Streams data from" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 },
};

static void
usage(const char *msg)
{
	if(msg)
		fprintf(stderr, "%s: Usage error: %s\n", argv_program, msg);
	argv_usage(g_args, ARGV_USAGE_DEFAULT);
	argv_cleanup(g_args);
	exit(EXIT_FAILURE);
}

static bool
parse_args(int argc, char **argv, struct replay *ctx)
{
	if (argv_process(g_args, argc, argv) != 0)
		return false;

	if (g_program_args.help)
		return false;

	if ((g_program_args.tcp_address != NULL) &&
		(g_program_args.tcp_port == NULL))
		usage("--tcp requires --port");

	ctx->content_type = (uint8_t *)g_program_args.content_type;
	ctx->len_content_type = strlen(g_program_args.content_type);
	return true;
}

static struct fstrm_writer *
init_writer(void)
{
	struct fstrm_writer *w;
	struct fstrm_writer_options *wopt;
	fstrm_res res;

	/* Setup writer options. */
	wopt = fstrm_writer_options_init();
	res = fstrm_writer_options_add_content_type(wopt,
				g_program_ctx.content_type,
				g_program_ctx.len_content_type);
	if (res != fstrm_res_success) {
		fstrm_writer_options_destroy(&wopt);
		return NULL;
	}

	if (g_program_args.unix_address != NULL) {
		struct fstrm_unix_writer_options *uwopt;

		if (g_program_args.tcp_port != NULL)
			fputs("Warning: Ignoring --port with --unix.\n", stderr);

		uwopt  = fstrm_unix_writer_options_init();
		fstrm_unix_writer_options_set_socket_path(uwopt, g_program_args.unix_address);
		w = fstrm_unix_writer_init(uwopt, wopt);
		fstrm_unix_writer_options_destroy(&uwopt);
		fstrm_writer_options_destroy(&wopt);
		if (w == NULL) {
			fputs("Error: fstrm_unix_writer_init() failed.\n", stderr);
			return NULL;
		}
	} else {
		struct fstrm_tcp_writer_options *twopt;
		unsigned long port;
		char *endptr;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;

	        /* Parse TCP listen port. */
	        port = strtoul(g_program_args.tcp_port, &endptr, 0);
	        if (*endptr != '\0' || port > UINT16_MAX)
	                usage("Failed to parse TCP listen port");

		/* Parse TCP listen address. */
		if ((inet_pton(AF_INET, g_program_args.tcp_address, &sin) != 1) &&
		    (inet_pton(AF_INET6, g_program_args.tcp_address, &sin6) != 1))
			usage("Failed to parse TCP listen address");

		twopt = fstrm_tcp_writer_options_init();
		fstrm_tcp_writer_options_set_socket_address(twopt, g_program_args.tcp_address);
		fstrm_tcp_writer_options_set_socket_port(twopt, g_program_args.tcp_port);

		w = fstrm_tcp_writer_init(twopt, wopt);
		fstrm_tcp_writer_options_destroy(&twopt);
		fstrm_writer_options_destroy(&wopt);

		if (w == NULL) {
			fputs("Error: fstrm_tcp_writer_init() failed.\n", stderr);
			return NULL;
		}
	}

	res = fstrm_writer_open(w);
	if (res != fstrm_res_success) {
		fstrm_writer_destroy(&w);
		fputs("Error: fstrm_writer_open() failed.\n", stderr);
		return NULL;
	}

	return w;
}

static void
process_file(const char *fname, struct fstrm_writer *w)
{
	struct fstrm_reader *r = NULL;
	struct fstrm_file_options *fopt = NULL;
	const struct fstrm_control *control = NULL;
	fstrm_res res;

	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, fname);

	/* Initialize file reader. */
	r = fstrm_file_reader_init(fopt, NULL);
	fstrm_file_options_destroy(&fopt);
	if (r == NULL) {
		fprintf(stderr, "Warning: failed to open %s, skipping\n", fname);
		return;
	}

	/* Check file content type. */
	res = fstrm_reader_get_control(r, FSTRM_CONTROL_START, &control);
	if (res != fstrm_res_success) {
		fprintf(stderr, "Warning: failed to read control frame from %s, skipping\n", fname);
		fstrm_reader_destroy(&r);
		return;
	}

	res = fstrm_control_match_field_content_type(control,
				g_program_ctx.content_type,
				g_program_ctx.len_content_type);
	if (res != fstrm_res_success) {
		fprintf(stderr, "Warning: content type mismatch for %s, skipping\n", fname);
		fstrm_reader_destroy(&r);
		return;
	}

	/* Loop over file data. */
	for (;;) {
		const uint8_t *data;
		size_t len_data;

		res = fstrm_reader_read(r, &data, &len_data);
		if (res == fstrm_res_success) {
			/* Write the data frame. */
			res = fstrm_writer_write(w, data, len_data);
			if (res != fstrm_res_success) {
				fputs("Error: write_data_frame() failed", stderr);
				exit(EXIT_FAILURE);
			}
		} else if (res == fstrm_res_stop) {
			/* Normal end of data stream. */
			res = fstrm_reader_get_control(r, FSTRM_CONTROL_STOP, &control);
			if (res != fstrm_res_success) {
				fprintf(stderr, "Error: unable to read STOP frame from %s.\n", fname);
			}
			break;
		} else {
			/* Abnormal end. */
			fprintf(stderr, "Error: fstrm_reader_read() failed.\n");
			break;
		}
	}
	fstrm_reader_destroy(&r);
}

int main(int argc, char **argv)
{
	int i;
	fstrm_res res;
	struct fstrm_writer *w = NULL;

	if (!parse_args(argc, argv, &g_program_ctx))
		usage(NULL);

	w = init_writer();
	if (w == NULL)
		exit(EXIT_FAILURE);

	for (i = 0; i < ARGV_ARRAY_COUNT(g_program_args.files); i++) {
		const char *in_fname;
		in_fname = ARGV_ARRAY_ENTRY(g_program_args.files, char *, i);
		process_file(in_fname, w);
	}

	res = fstrm_writer_close(w);
	if (res != fstrm_res_success)
		fputs("Error: fstrm_writer_close() failed", stderr);

	fstrm_writer_destroy(&w);
	return 0;
}
