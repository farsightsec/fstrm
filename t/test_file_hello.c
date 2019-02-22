/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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

/**
 * test_file_hello: simple "hello world" fstrm_file test.
 *
 * Writes several messages to a test file, then reads the test file and
 * verifies the contents of the test messages.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstrm.h>

static const char *test_pattern = "Hello world #%d";
static const char *test_content_type = "test:hello";
static const int num_iterations = 1000;

static fstrm_res
write_message(struct fstrm_writer *w, int i)
{
	fstrm_res res;
	char buf[100] = {0};

	sprintf(buf, test_pattern, i);
	res = fstrm_writer_write(w, buf, strlen(buf) + 1);
	if (res != fstrm_res_success) {
		printf("%s: fstrm_writer_write() failed.\n", __func__);
		return res;
	}

	return fstrm_res_success;
}

static fstrm_res
read_message(struct fstrm_reader *r, int i)
{
	fstrm_res res;
	char buf[100] = {0};
	const uint8_t *rbuf = NULL;
	size_t len_rbuf = 0;

	sprintf(buf, test_pattern, i);
	res = fstrm_reader_read(r, &rbuf, &len_rbuf);
	if (res != fstrm_res_success) {
		printf("%s: fstrm_reader_read() failed.\n", __func__);
		return res;
	}

	if (len_rbuf != strlen(buf) + 1) {
		printf("%s: string length comparison failed.\n", __func__);
		return fstrm_res_failure;
	}

	if (memcmp(buf, rbuf, len_rbuf) != 0) {
		printf("%s: string data comparison failed.\n", __func__);
		return fstrm_res_failure;
	}

	return fstrm_res_success;
}

int
main(void)
{
	int rv = 0;
	fstrm_res res = fstrm_res_failure;
	struct fstrm_file_options *fopt = NULL;
	struct fstrm_reader *r = NULL;
	struct fstrm_writer *w = NULL;
	struct fstrm_reader_options *ropt = NULL;
	struct fstrm_writer_options *wopt = NULL;

	/* Generate temporary filename. */
	char file_path[] = "./test.fstrm.XXXXXX";
	rv = mkstemp(file_path);
	if (rv < 0) {
		printf("Error: mkstemp() failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/* File options. */
	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, file_path);

	/* Writer options. */
	wopt = fstrm_writer_options_init();
	res = fstrm_writer_options_add_content_type(wopt,
		test_content_type, strlen(test_content_type));
	if (res != fstrm_res_success) {
		printf("Error: fstrm_writer_options_add_content_type() failed.\n");
		goto fail;
	}

	/* Open writer. */
	printf("Opening file %s for writing.\n", file_path);
	w = fstrm_file_writer_init(fopt, wopt);
	if (!w) {
		printf("Error: fstrm_file_writer_init() failed.\n");
		goto fail;
	}
	res = fstrm_writer_open(w);
	if (res != fstrm_res_success) {
		printf("Error: fstrm_writer_open() failed.\n");
		goto fail;
	}

	/* Double open. */
	printf("Doing a double open.\n");
	res = fstrm_writer_open(w);
	if (res != fstrm_res_success) {
		printf("Error: fstrm_writer_open() failed.\n");
		goto fail;
	}

	/* Write hello messages. */
	for (int i = 0; i < num_iterations; i++) {
		res = write_message(w, i);
		if (res != fstrm_res_success) {
			printf("Error: write_message() failed.\n");
			goto fail;
		}
	}
	printf("Wrote %d messages.\n", num_iterations);

	/* Close writer. */
	res = fstrm_writer_destroy(&w);
	if (res != fstrm_res_success) {
		printf("Error: fstrm_writer_destroy() failed.\n");
		goto fail;
	}

	/* Reader options. */
	ropt = fstrm_reader_options_init();
	res = fstrm_reader_options_add_content_type(ropt,
		test_content_type, strlen(test_content_type));
	if (res != fstrm_res_success) {
		printf("Error: fstrm_reader_options_add_content_type() failed.\n");
		goto fail;
	}

	/* Open reader. */
	printf("Opening file %s for reading.\n", file_path);
	r = fstrm_file_reader_init(fopt, ropt);
	if (!r) {
		printf("Error: fstrm_file_reader_init() failed.\n");
		goto fail;
	}
	res = fstrm_reader_open(r);
	if (res != fstrm_res_success) {
		printf("Error: fstrm_reader_open() failed.\n");
		goto fail;
	}

	/* Read hello messages. */
	for (int i = 0; i < num_iterations; i++) {
		res = read_message(r, i);
		if (res != fstrm_res_success) {
			printf("Error: read_message() failed.\n");
			goto fail;
		}
	}
	printf("Read %d messages.\n", num_iterations);

	/*
	 * The next read should fail with fstrm_res_stop, since we read exactly
	 * the number of messages in the file.
	 */
	const uint8_t *data = NULL;
	size_t len_data = 0;
	res = fstrm_reader_read(r, &data, &len_data);
	if (res != fstrm_res_stop) {
		printf("Error: got unexpected result from fstrm_reader_read(): %d.\n", res);
		res = fstrm_res_failure;
		goto fail;
	}

	/* Close reader. */
	(void)fstrm_reader_destroy(&r);

	res = fstrm_res_success;
fail:
	/* Cleanup. */
	printf("Unlinking file %s.\n", file_path);
	(void)unlink(file_path);

	fstrm_file_options_destroy(&fopt);
	(void)fstrm_reader_destroy(&r);
	(void)fstrm_writer_destroy(&w);
	fstrm_reader_options_destroy(&ropt);
	fstrm_writer_options_destroy(&wopt);

	if (res == fstrm_res_success)
		return EXIT_SUCCESS;
	return EXIT_FAILURE;
}
