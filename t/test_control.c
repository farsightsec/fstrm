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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstrm.h>

#include "libmy/print_string.h"

/* Placeholder "Content Type" values. */
static const uint8_t wharrgarbl[] = "wharr\x00garbl";
static const uint8_t wharrgarblv2[] = "wharrgarblv2";

/*
 * Valid control frames. These come in two variants, the *_wh suffixed ones that
 * include the escape sequence and control frame length header which must be
 * encoded/decoded with the FSTRM_CONTROL_FLAG_WITH_HEADER flag, and the
 * un-suffixed ones which must be encoded/decoded without the
 * FSTRM_CONTROL_FLAG_WITH_HEADER flag.
 */

static const uint8_t accept_1[] = {
	/* FSTRM_CONTROL_ACCEPT. */
	0x00, 0x00, 0x00, 0x01,
};

static const uint8_t accept_1_wh[] = {
	/* Escape sequence. */
	0x00, 0x00, 0x00, 0x00,

	/* Control frame length: 4 bytes of control frame payload. */
	0x00, 0x00, 0x00, 0x04,

	/* FSTRM_CONTROL_ACCEPT. */
	0x00, 0x00, 0x00, 0x01,
};

static const uint8_t accept_2[] = {
	/* FSTRM_CONTROL_ACCEPT. */
	0x00, 0x00, 0x00, 0x01,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};

static const uint8_t accept_2_wh[] = {
	/* Escape sequence. */
	0x00, 0x00, 0x00, 0x00,

	/* Control frame length: 23 bytes of control frame payload. */
	0x00, 0x00, 0x00, 0x17,

	/* FSTRM_CONTROL_ACCEPT. */
	0x00, 0x00, 0x00, 0x01,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};

static const uint8_t accept_3[] = {
	/* FSTRM_CONTROL_ACCEPT. */
	0x00, 0x00, 0x00, 0x01,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0c (12 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0c,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 'g', 'a', 'r', 'b', 'l', 'v', '2',
};

static const uint8_t accept_3_wh[] = {
	/* Escape sequence. */
	0x00, 0x00, 0x00, 0x00,

	/* Control frame length: 43 bytes of control frame payload. */
	0x00, 0x00, 0x00, 0x2b,

	/* FSTRM_CONTROL_ACCEPT. */
	0x00, 0x00, 0x00, 0x01,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0c (12 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0c,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 'g', 'a', 'r', 'b', 'l', 'v', '2',
};

static const uint8_t ready_1[] = {
	/* FSTRM_CONTROL_READY. */
	0x00, 0x00, 0x00, 0x04,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,
	/* 0x0c (12 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0c,
	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 'g', 'a', 'r', 'b', 'l', 'v', '2',
};

static const uint8_t start_1[] = {
	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,
};

static const uint8_t start_1_wh[] = {
	/* Escape sequence. */
	0x00, 0x00, 0x00, 0x00,

	/* Control frame length: 4 bytes of control frame payload. */
	0x00, 0x00, 0x00, 0x04,

	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,
};

static const uint8_t start_2[] = {
	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,

	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,

	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};

static const uint8_t start_2_wh[] = {
	/* Escape sequence. */
	0x00, 0x00, 0x00, 0x00,

	/* Control frame length: 23 bytes of control frame payload. */
	0x00, 0x00, 0x00, 0x17,

	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,

	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,

	/* The CONTENT_TYPE field payload. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};

static const uint8_t stop_1[] = {
	/* FSTRM_CONTROL_STOP. */
	0x00, 0x00, 0x00, 0x03,
};

static const uint8_t stop_1_wh[] = {
	/* Escape sequence. */
	0x00, 0x00, 0x00, 0x00,

	/* Control frame length: 4 bytes of control frame payload. */
	0x00, 0x00, 0x00, 0x04,

	/* FSTRM_CONTROL_STOP. */
	0x00, 0x00, 0x00, 0x03,
};

/*
 * Structure for encoding parameters and expected results for the above control
 * tests.
 */
struct control_test {
	const uint8_t		*frame;
	size_t			len_frame;
	fstrm_control_type	type;
	uint32_t		flags;
	const uint8_t		*content_type;
	size_t			len_content_type;
	fstrm_res		match_res;
};

static const struct control_test control_tests[] = {
	{
		.frame		= accept_1,
		.len_frame	= sizeof(accept_1),
		.type		= FSTRM_CONTROL_ACCEPT,
	},
	{
		.frame		= accept_1_wh,
		.len_frame	= sizeof(accept_1_wh),
		.type		= FSTRM_CONTROL_ACCEPT,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
	},
	{
		.frame		= accept_2,
		.len_frame	= sizeof(accept_2),
		.type		= FSTRM_CONTROL_ACCEPT,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= accept_2_wh,
		.len_frame	= sizeof(accept_2_wh),
		.type		= FSTRM_CONTROL_ACCEPT,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= accept_3,
		.len_frame	= sizeof(accept_3),
		.type		= FSTRM_CONTROL_ACCEPT,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= accept_3_wh,
		.len_frame	= sizeof(accept_3_wh),
		.type		= FSTRM_CONTROL_ACCEPT,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= accept_3,
		.len_frame	= sizeof(accept_3),
		.type		= FSTRM_CONTROL_ACCEPT,
		.content_type	= wharrgarblv2,
		.len_content_type = sizeof(wharrgarblv2) - 1,
	},
	{
		.frame		= accept_3_wh,
		.len_frame	= sizeof(accept_3_wh),
		.type		= FSTRM_CONTROL_ACCEPT,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
		.content_type	= wharrgarblv2,
		.len_content_type = sizeof(wharrgarblv2) - 1,
	},
	{
		.frame		= ready_1,
		.len_frame	= sizeof(ready_1),
		.type		= FSTRM_CONTROL_READY,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= ready_1,
		.len_frame	= sizeof(ready_1),
		.type		= FSTRM_CONTROL_READY,
		.content_type	= wharrgarblv2,
		.len_content_type = sizeof(wharrgarblv2) - 1,
	},
	{
		.frame		= start_1,
		.len_frame	= sizeof(start_1),
		.type		= FSTRM_CONTROL_START,
	},
	{
		.frame		= start_1_wh,
		.len_frame	= sizeof(start_1_wh),
		.type		= FSTRM_CONTROL_START,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
	},
	{
		.frame		= start_1,
		.len_frame	= sizeof(start_1),
		.type		= FSTRM_CONTROL_START,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= start_1_wh,
		.len_frame	= sizeof(start_1_wh),
		.type		= FSTRM_CONTROL_START,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= start_2,
		.len_frame	= sizeof(start_2),
		.type		= FSTRM_CONTROL_START,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= start_2,
		.len_frame	= sizeof(start_2),
		.type		= FSTRM_CONTROL_START,
		.content_type	= wharrgarblv2,
		.len_content_type = sizeof(wharrgarblv2) - 1,
		.match_res	= fstrm_res_failure,
	},
	{
		.frame		= start_2_wh,
		.len_frame	= sizeof(start_2_wh),
		.type		= FSTRM_CONTROL_START,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
		.content_type	= wharrgarbl,
		.len_content_type = sizeof(wharrgarbl) - 1,
	},
	{
		.frame		= stop_1,
		.len_frame	= sizeof(stop_1),
		.type		= FSTRM_CONTROL_STOP,
		.match_res	= fstrm_res_failure,
	},
	{
		.frame		= stop_1_wh,
		.len_frame	= sizeof(stop_1_wh),
		.type		= FSTRM_CONTROL_STOP,
		.flags		= FSTRM_CONTROL_FLAG_WITH_HEADER,
		.match_res	= fstrm_res_failure,
	},

	{ .frame = NULL },
};

/* Invalid control frames. */

static const uint8_t invalid_1[] = { 0xff, };

static const uint8_t invalid_2[] = { 0xff, 0xff, };

static const uint8_t invalid_3[] = { 0xff, 0xff, 0xff, };

static const uint8_t invalid_4[] = { 0xff, 0xff, 0xff, };

static const uint8_t invalid_5[] = { 0xff, 0xff, 0xff, 0xff, };

static const uint8_t invalid_6[] = { 0xff, 0xff, 0xff, 0xff, 0xff };

static const uint8_t invalid_7[] = { 0xab, 0xad, 0x1d, 0xea, };

static const uint8_t invalid_8[] = {
	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,

	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,

	/* The CONTENT_TYPE field payload. Only 10 bytes here. Short read! */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b',
};

static const uint8_t invalid_9[] = {
	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,

	/* 0x0b (11 bytes) of CONTENT_TYPE field payload follow. */
	0x00, 0x00, 0x00, 0x0b,

	/* The CONTENT_TYPE field payload. An extra byte here. */
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l', 'z',
};

static const uint8_t invalid_10[] = {
	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,

	/* Incomplete control field. */
	0x00,
};

static const uint8_t invalid_11[] = {
	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,

	/* Incomplete control field. */
	0x00, 0x00, 0x00,
};

static const uint8_t invalid_12[] = {
	/* FSTRM_CONTROL_START. */
	0x00, 0x00, 0x00, 0x02,

	/* FSTRM_CONTROL_FIELD_CONTENT_TYPE. */
	0x00, 0x00, 0x00, 0x01,

	/* No CONTENT_TYPE field payload. This is required. */
};

struct bytes {
	const uint8_t	*bytes;
	size_t		len;
};

static const struct bytes invalid[] = {
	{ invalid_1, sizeof(invalid_1), },
	{ invalid_2, sizeof(invalid_2), },
	{ invalid_3, sizeof(invalid_3), },
	{ invalid_4, sizeof(invalid_4), },
	{ invalid_5, sizeof(invalid_5), },
	{ invalid_6, sizeof(invalid_6), },
	{ invalid_7, sizeof(invalid_7), },
	{ invalid_8, sizeof(invalid_8), },
	{ invalid_9, sizeof(invalid_9), },
	{ invalid_10, sizeof(invalid_10), },
	{ invalid_11, sizeof(invalid_11), },
	{ invalid_12, sizeof(invalid_12), },
	{ NULL, 0 },
};

static fstrm_res
match_content_type(struct fstrm_control *c,
		   const uint8_t *content_type,
		   size_t len_content_type)
{
	fstrm_res res;

	res = fstrm_control_match_field_content_type(c, content_type, len_content_type);
	printf("  Control frame is %scompatible with CONTENT_TYPE (%zd bytes): ",
	       res == fstrm_res_success ? "" : "NOT ",
	       len_content_type);
	print_string(content_type, len_content_type, stdout);
	putchar('\n');

	return res;
}

static fstrm_res
decode_control_frame(struct fstrm_control *c,
		     const uint8_t *control_frame,
		     size_t len_control_frame,
		     uint32_t flags)
{
	fstrm_res res;
	fstrm_control_type type;

	res = fstrm_control_decode(c, control_frame, len_control_frame, flags);
	if (res == fstrm_res_success) {
		printf("Successfully decoded frame (%zd bytes):\n  ",
		       len_control_frame);
		print_string(control_frame, len_control_frame, stdout);
		putchar('\n');
	} else {
		printf("Failed to decode frame (%zd bytes):\n  ",
		       len_control_frame);
		print_string(control_frame, len_control_frame, stdout);
		putchar('\n');
		return res;
	}

	res = fstrm_control_get_type(c, &type);
	if (res != fstrm_res_success) {
		puts("  fstrm_control_get_type() failed.");
		return res;
	}
	printf("  The control frame is of type %s (0x%08x).\n",
	       fstrm_control_type_to_str(type), type);

	size_t n_ctype;
	res = fstrm_control_get_num_field_content_type(c, &n_ctype);
	if (res != fstrm_res_success) {
		puts("  fstrm_control_get_num_field_content_type() failed.");
		return res;
	}
	for (size_t idx = 0; idx < n_ctype; idx++) {
		const uint8_t *content_type;
		size_t len_content_type;

		res = fstrm_control_get_field_content_type(c, idx,
			&content_type, &len_content_type);
		if (res == fstrm_res_success) {
			printf("  The control frame has a CONTENT_TYPE field (%zd bytes): ",
			       len_content_type);
			print_string(content_type, len_content_type, stdout);
			putchar('\n');
		} else if (res == fstrm_res_failure) {
			puts("  The control frame does not have any CONTENT_TYPE fields.");
		} else {
			/* Not reached. */
			assert(0);
		}
	}

	return fstrm_res_success;
}

static void
test_reencode_frame(struct fstrm_control *c,
		    const uint8_t *control_frame,
		    size_t len_control_frame,
		    uint32_t flags)
{
	printf("Running %s().\n", __func__);

	fstrm_res res;
	int cmp;
	size_t len_new_frame = 0, len_new_frame_2 = 0;

	res = fstrm_control_encoded_size(c, &len_new_frame, flags);
	assert(res == fstrm_res_success);
	printf("Need %zd bytes for new frame.\n", len_new_frame);
	assert(len_new_frame <= FSTRM_CONTROL_FRAME_LENGTH_MAX);
	uint8_t new_frame[len_new_frame];

	len_new_frame_2 = len_new_frame;
	res = fstrm_control_encode(c, new_frame, &len_new_frame_2, flags);
	assert(res == fstrm_res_success);
	printf("Successfully encoded a new frame (%zd bytes):\n  ",
	       len_new_frame_2);
	print_string(new_frame, len_new_frame_2, stdout);
	putchar('\n');
	assert(len_new_frame == len_new_frame_2);
	assert(len_new_frame == len_control_frame);

	cmp = memcmp(control_frame, new_frame, len_control_frame);
	assert(cmp == 0);
	puts("New frame is identical to original frame.");
}

static void
test_reencode_frame_static(struct fstrm_control *c,
			   const uint8_t *control_frame,
			   size_t len_control_frame,
			   uint32_t flags)
{
	printf("Running %s().\n", __func__);

	fstrm_res res;
	int cmp;
	uint8_t new_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_new_frame = sizeof(new_frame);

	res = fstrm_control_encode(c, new_frame, &len_new_frame, flags);
	assert(res == fstrm_res_success);
	assert(len_new_frame <= FSTRM_CONTROL_FRAME_LENGTH_MAX);
	printf("Successfully encoded a new frame (%zd bytes):\n  ", len_new_frame);
	print_string(new_frame, len_new_frame, stdout);
	putchar('\n');

	cmp = memcmp(control_frame, new_frame, len_control_frame);
	assert(cmp == 0);
	puts("New frame is identical to original frame.");
}

static void
test_control_test(struct fstrm_control *c, const struct control_test *test)
{
	printf("Running %s().\n", __func__);

	if (test->flags & FSTRM_CONTROL_FLAG_WITH_HEADER)
		printf("Control frames include escape sequence and control frame length.\n"
		       "  (FSTRM_CONTROL_FLAG_WITH_HEADER enabled.)\n");

	fstrm_res res;
	fstrm_control_type type;

	res = decode_control_frame(c, test->frame, test->len_frame, test->flags);
	assert(res == fstrm_res_success);
	res = fstrm_control_get_type(c, &type);
	assert(res == fstrm_res_success);
	assert(type == test->type);

	res = match_content_type(c, test->content_type, test->len_content_type);
	assert(res == test->match_res);

	test_reencode_frame(c, test->frame, test->len_frame, test->flags);
	test_reencode_frame_static(c, test->frame, test->len_frame, test->flags);
}

static void
test_control_tests(struct fstrm_control *c)
{
	printf("Running %s().\n\n", __func__);

	for (const struct control_test *test = &control_tests[0];
	     test->frame != NULL;
	     test++)
	{
		test_control_test(c, test);
		putchar('\n');
	}
}

static void
test_invalid(struct fstrm_control *c)
{
	printf("Running %s().\n", __func__);

	for (const struct bytes *test = &invalid[0];
	     test->bytes != NULL;
	     test++)
	{
		fstrm_res res;
		res = decode_control_frame(c, test->bytes, test->len, 0);
		assert(res != fstrm_res_success);
	}
}

int
main(void)
{
	struct fstrm_control *c;

	c = fstrm_control_init();

	puts("====> The following tests must succeed. <====");
	test_control_tests(c);

	puts("====> The following tests must fail. <====");
	test_invalid(c);

	fstrm_control_destroy(&c);

	return EXIT_SUCCESS;
}
