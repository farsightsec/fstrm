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

/* The maximum data frame size in bytes we're willing to process. */
#define MAX_DATA_FRAME_SIZE		1048576

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
	fprintf(stderr, "Data frame (%u bytes):\n", len);
	putchar(' ');
	print_string(ubuf_data(data_buf), len, stdout);
	putchar('\n');
	return true;
}

static bool
dump_control_frame(FILE *fp, struct fstrm_control *c)
{
	fstrm_res res;
	uint32_t len;
	uint8_t control_frame[FSTRM_MAX_CONTROL_FRAME_LENGTH];

	/* Read the control frame length. */
	if (!read_be32(fp, &len)) {
		fprintf(stderr, "%s: encoding error reading control frame length\n", __func__);
		return false;
	}

	/* Read the control frame. */
	if (len > sizeof(control_frame)) {
		fprintf(stderr, "%s: control frame too large (%u > %zd)\n", __func__,
			len, sizeof(control_frame));
		return false;
	}
	if (!read_data(fp, control_frame, len)) {
		fprintf(stderr, "%s: encoding error reading control frame\n", __func__);
		return false;
	}

	/* Decode the control frame. */
	fstrm_control_type type;
	res = fstrm_control_decode(c, control_frame, len, 0);
	if (res != FSTRM_RES_SUCCESS)
		return false;

	/* Print the control frame. */
	res = fstrm_control_get_type(c, &type);
	if (res != FSTRM_RES_SUCCESS)
		return false;
	fprintf(stderr, "%s [0x%08x] (%u bytes):\n ",
		fstrm_control_type_to_str(type), type, len);
	print_string(control_frame, len, stderr);
	fputc('\n', stderr);

	/* Print the "Content Type". */
	const uint8_t *content_type;
	size_t len_content_type;
	res = fstrm_control_get_field_content_type(c,
		&content_type, &len_content_type);
	if (res == FSTRM_RES_SUCCESS) {
		fprintf(stderr, "%s [0x%08x] (%zd bytes):\n ",
			fstrm_control_field_type_to_str(FSTRM_CONTROL_FIELD_CONTENT_TYPE),
			FSTRM_CONTROL_FIELD_CONTENT_TYPE,
			len_content_type);
		print_string(content_type, len_content_type, stderr);
		fputc('\n', stderr);
	}

	return true;

}

static bool
dump_file(FILE *fp, struct fstrm_control *c)
{
	fstrm_control_type type;
	uint32_t len;
	uint8_t control_frame[FSTRM_MAX_CONTROL_FRAME_LENGTH];
	uint32_t len_control_frame;
	fstrm_res res;

	/* Read the start frame. */
	if (!read_be32(fp, &len)) {
		fprintf(stderr, "%s: error reading start of stream", __func__);
		return false;
	}
	if (len != 0) {
		fprintf(stderr, "%s: error reading escape sequence", __func__);
	}
	if (!dump_control_frame(fp, c))
		return false;
	res = fstrm_control_get_type(c, &type);
	if (res != FSTRM_RES_SUCCESS)
		return false;
	if (type != FSTRM_CONTROL_START) {
		fprintf(stderr, "%s: unexpected control frame type at beginning of stream\n",
			__func__);
		return false;
	}

	for (;;) {
		/* Read the frame length. */
		if (!read_be32(fp, &len))
			return false;

		if (len == 0) {
			/* This is a control frame. */

			/* Read the control frame length. */
			if (!read_be32(fp, &len_control_frame))
				return false;
			if (len_control_frame > FSTRM_MAX_CONTROL_FRAME_LENGTH)
				return false;

			/* Read the control frame payload. */
			if (!read_data(fp, control_frame, len_control_frame))
				return false;

			/* Decode the control frame. */
			res = fstrm_control_decode(c,
				control_frame, len_control_frame, 0);
			if (res != FSTRM_RES_SUCCESS)
				return false;

			/* Print the control frame. */
			res = fstrm_control_get_type(c, &type);
			if (res != FSTRM_RES_SUCCESS)
				return false;
			fprintf(stderr, "%s [0x%08x] (%u bytes):\n ",
			       fstrm_control_type_to_str(type), type,
			       len_control_frame);
			print_string(control_frame, len_control_frame, stderr);
			fputc('\n', stderr);

			/* Break if this is the end of the stream. */
			if (type == FSTRM_CONTROL_STOP)
				break;
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
	struct fstrm_control *c;
	FILE *fp;
	bool res;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <INPUT FILE>\n", argv[0]);
		fprintf(stderr, "Dumps a Frame Streams formatted input file.\n\n");
		return EXIT_FAILURE;
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "%s: unable to open input file %s: %s\n",
			argv[0], argv[1], strerror(errno));
		return EXIT_FAILURE;
	}
	c = fstrm_control_init();
	data_buf = ubuf_init(512);
	res = dump_file(fp, c);
	ubuf_destroy(&data_buf);
	fstrm_control_destroy(&c);
	fclose(fp);

	if (res) {
		return EXIT_SUCCESS;
	} else {
		fprintf(stderr, "%s: error decoding input\n", argv[0]);
		return EXIT_FAILURE;
	}
}
