/*
 * Copyright (c) 2018 by Farsight Security, Inc.
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

#include <sys/uio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <fstrm.h>

static fstrm_res
process_start_frame(struct fstrm_reader *r, struct fstrm_writer_options *wopt)
{
	fstrm_res res;
	const struct fstrm_control *control = NULL;
	size_t n_content_type = 0;
	const uint8_t *content_type = NULL;
	size_t len_content_type = 0;

	res = fstrm_reader_get_control(r, FSTRM_CONTROL_START, &control);
	if (res != fstrm_res_success)
		return res;

	res = fstrm_control_get_num_field_content_type(control, &n_content_type);
	if (res != fstrm_res_success)
		return res;
	if (n_content_type > 0) {
		res = fstrm_control_get_field_content_type(control, 0,
			&content_type, &len_content_type);
		if (res != fstrm_res_success)
			return res;
	}

	if (wopt != NULL && content_type != NULL) {
		res = fstrm_writer_options_add_content_type(wopt,
			content_type, len_content_type);
		if (res != fstrm_res_success)
			return res;
	}

	return fstrm_res_success;
}

int main(int argc, char **argv)
{
	const char *output_type = NULL;
	const char *output_addr = NULL;
	const char *input_fname = NULL;

	fstrm_res res = fstrm_res_failure;
	struct fstrm_file_options *fopt = NULL;
	struct fstrm_writer_options *wopt = NULL;
	struct fstrm_reader *r = NULL;
	struct fstrm_writer *w = NULL;

	int rv = EXIT_FAILURE;

	/* Args. */
	if (argc != 4 || (strcmp(argv[1], "tcp") && strcmp(argv[1], "unix")))  {
		fprintf(stderr, "Usage: %s (tcp|unix) (address:port|path) <INPUT FILE>\n", argv[0]);
		fprintf(stderr, "Replays a Frame Streams formatted input file.\n\n");
		return EXIT_FAILURE;
	}
	output_type = argv[1];
	output_addr = argv[2];
	input_fname = argv[3];

	/* Setup file reader options. */
	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, input_fname);

	/* Initialize file reader. */
	r = fstrm_file_reader_init(fopt, NULL);
	if (r == NULL) {
		fputs("Error: fstrm_file_reader_init() failed.\n", stderr);
		goto out;
	}
	res = fstrm_reader_open(r);
	if (res != fstrm_res_success) {
		fputs("Error: fstrm_reader_open() failed.\n", stderr);
		goto out;
	}

	/* Setup writer options. */
	wopt = fstrm_writer_options_init();

	/* Copy "content type" from the reader's START frame. */
	res = process_start_frame(r, wopt);
	if (res != fstrm_res_success) {
		fputs("Error: process_start_frame() failed.\n", stderr);
		goto out;
	}

	if (!strcmp(output_type, "unix")) {
		struct fstrm_unix_writer_options *uwopt;

		uwopt  = fstrm_unix_writer_options_init();
		fstrm_unix_writer_options_set_socket_path(uwopt, output_addr);
		w = fstrm_unix_writer_init(uwopt, wopt);
		fstrm_unix_writer_options_destroy(&uwopt);
		if (w == NULL) {
			fputs("Error: fstrm_unix_writer_init() failed.\n", stderr);
			goto out;
		}
	} else {
		struct fstrm_tcp_writer_options *twopt;
		char *addr, *port;

		addr = strdup(output_addr);

		addr = strtok(addr, ":");
		port = strtok(NULL, ":");

		twopt = fstrm_tcp_writer_options_init();
		fstrm_tcp_writer_options_set_socket_address(twopt, addr);
		fstrm_tcp_writer_options_set_socket_port(twopt, port);

		w = fstrm_tcp_writer_init(twopt, wopt);
		fstrm_tcp_writer_options_destroy(&twopt);
		free(addr);

		if (w == NULL) {
			fputs("Error: fstrm_tcp_writer_init() failed.\n", stderr);
			goto out;
		}
	}

	res = fstrm_writer_open(w);
	if (res != fstrm_res_success) {
		fstrm_writer_destroy(&w);
		fputs("Error: fstrm_writer_open() failed.\n", stderr);
		goto out;
	}

	/* Loop over data frames. */
	for (;;) {
		const uint8_t *data;
		size_t len_data;

		res = fstrm_reader_read(r, &data, &len_data);
		if (res == fstrm_res_success) {
			/* Write the data frame. */
			res = fstrm_writer_write(w, data, len_data);
			if (res != fstrm_res_success) {
				fprintf(stderr, "Error: write_data_frame() failed.\n");
				goto out;
			}
		} else if (res == fstrm_res_stop) {
			const struct fstrm_control *control = NULL;
			/* Normal end of data stream. */
			res = fstrm_reader_get_control(r, FSTRM_CONTROL_STOP, &control);
			if (res != fstrm_res_success) {
				fprintf(stderr, "Error: unable to read STOP frame.\n");
				goto out;
			}
			rv = EXIT_SUCCESS;
			break;
		} else {
			/* Abnormal end. */
			fprintf(stderr, "Error: fstrm_reader_read() failed.\n");
			goto out;
		}
	}

out:
	/* Cleanup options. */
	fstrm_writer_options_destroy(&wopt);

	/* Cleanup reader. */
	fstrm_reader_destroy(&r);

	/* Cleanup writer. */
	if (w != NULL) {
		res = fstrm_writer_close(w);
		if (res != fstrm_res_success) {
			fprintf(stderr, "Error: fstrm_writer_close() failed.\n");
			rv = EXIT_FAILURE;
		}
		fstrm_writer_destroy(&w);
	}

	return rv;
}
