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

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libmy/print_string.h"
#include "libmy/ubuf.h"

#include <fstrm.h>

#if HAVE_DECL_FREAD_UNLOCKED
# define fread fread_unlocked
#endif

#if HAVE_DECL_FWRITE_UNLOCKED
# define fwrite fwrite_unlocked
#endif

#define MAX_CONTROL_FRAME_SIZE		512	/* bytes */
#define MAX_DATA_FRAME_SIZE		1048576	/* bytes */

static size_t	count_read;
static size_t	bytes_read;
static ubuf	*data_buf;

static bool
read_data(FILE *fp, void *buf, size_t len)
{
	size_t n_bytes;

	n_bytes = fread(buf, 1, len, fp);

	if (ferror(fp)) {
		fprintf(stderr, "%s: fread() failed\n", __func__);
		return false;
	}

	if (feof(fp)) {
		fprintf(stderr, "%s: fread() returned unexpected EOF\n", __func__);
		return false;
	}

	if (n_bytes != len) {
		fprintf(stderr, "%s: tried to read %zd bytes, only got %zd\n",
			__func__, len, n_bytes);
		return false;
	}

	return true;
}

static inline uint32_t
unpack_be32(const void *buf)
{
	uint32_t buf_value;
	memcpy(&buf_value, buf, sizeof(buf_value));
	return ntohl(buf_value);
}

static bool
read_be32(FILE *fp, uint32_t *out)
{
	uint32_t be32;

	if (read_data(fp, &be32, sizeof(be32))) {
		*out = ntohl(be32);
		return true;
	} else {
		return false;
	}
}

static bool
dump_data_frame(FILE *fp, uint32_t len)
{
	if (len > MAX_DATA_FRAME_SIZE) {
		fprintf(stderr, "%s: data frame too large (%u > %u)\n",
			__func__, len, MAX_DATA_FRAME_SIZE);
		return false;
	}
	ubuf_clip(data_buf, 0);
	ubuf_reserve(data_buf, len);
	if (!read_data(fp, ubuf_ptr(data_buf), len))
		return false;
	bytes_read += len;
	count_read += 1;
	printf("Data frame (%u bytes): ", len);
	print_string(ubuf_data(data_buf), len, stdout);
	putchar('\n');
	return true;
}

static bool
read_control_frame(FILE *fp,
		   uint8_t *control_frame,
		   uint32_t *control_frame_len,
		   uint32_t *control_frame_type)
{
	uint32_t len;

	/* Read the control frame length. */
	if (!read_be32(fp, &len)) {
		fprintf(stderr, "%s: encoding error reading control frame length\n", __func__);
		return false;
	}

	/* Read the control frame. */
	if (len > *control_frame_len) {
		fprintf(stderr, "%s: control frame too large (%u > %u)\n", __func__,
			len, *control_frame_len);
		return false;
	}
	if (!read_data(fp, control_frame, len)) {
		fprintf(stderr, "%s: encoding error reading control frame\n", __func__);
		return false;
	}
	*control_frame_len = len;
	*control_frame_type = unpack_be32(control_frame);

	return true;
}

static bool
read_control_start(FILE *fp)
{
	uint32_t len;
	uint8_t control_frame[MAX_CONTROL_FRAME_SIZE];
	uint32_t control_frame_len = sizeof(control_frame);
	uint32_t control_frame_type = 0;

	/* Read the outer frame length. */
	if (!read_be32(fp, &len))
		return false;

	/* The outer frame length must be zero, since this is a control frame. */
	if (len != 0) {
		fprintf(stderr, "%s: encoding error reading frame length\n", __func__);
		return false;
	}

	/* Read a control frame. */
	if (!read_control_frame(fp,
				control_frame,
				&control_frame_len,
				&control_frame_type))
	{
		return false;
	}

	/* Check if the control frame is a start frame. */
	if (control_frame_type == FSTRM_CONTROL_START) {
		fprintf(stderr, "Control frame [START] (%u bytes): ", control_frame_len);
		print_string(control_frame, control_frame_len, stderr);
		fputc('\n', stderr);
	} else {
		fprintf(stderr, "%s: encoding error parsing start control frame\n", __func__);
		return false;
	}

	return true;
}

static bool
dump_file(FILE *fp)
{
	uint32_t len;
	uint8_t control_frame[MAX_CONTROL_FRAME_SIZE];
	uint32_t control_frame_len = sizeof(control_frame);
	uint32_t control_frame_type = 0;

	/* Read the start frame. */
	if (!read_control_start(fp))
		return false;

	for (;;) {
		/* Read the frame length. */
		if (!read_be32(fp, &len))
			return false;

		if (len == 0) {
			/* This is a control frame. */
			control_frame_len = sizeof(control_frame);
			control_frame_type = 0;
			if (!read_control_frame(fp,
						control_frame,
						&control_frame_len,
						&control_frame_type))
			{
				return false;
			}
			if (control_frame_type == FSTRM_CONTROL_STOP) {
				fprintf(stderr, "Control frame [STOP] (%u bytes): ",
					control_frame_len);
				print_string(control_frame, control_frame_len, stderr);
				fputc('\n', stderr);
				break;
			}
		} else {
			/* This is a data frame. */
			if (!dump_data_frame(fp, len))
				return false;
		}
	}
	return true;
}

int
main(int argc, char **argv)
{
	FILE *fp;
	bool res;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <INPUT FILE>\n", argv[0]);
		fprintf(stderr, "Dumps a FrameStreams formatted input file.\n\n");
		return EXIT_FAILURE;
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "%s: unable to open input file %s: %s\n",
			argv[0], argv[1], strerror(errno));
		return EXIT_FAILURE;
	}

	data_buf = ubuf_init(512);
	res = dump_file(fp);
	ubuf_destroy(&data_buf);
	fclose(fp);
	fprintf(stderr, "%s: bytes_read= %zd count_read= %zd\n", argv[0],
		bytes_read, count_read);
	if (res)
		return EXIT_SUCCESS;
	fprintf(stderr, "%s: error decoding input\n", argv[0]);
	return EXIT_FAILURE;
}
