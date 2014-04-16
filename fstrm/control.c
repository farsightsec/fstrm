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

#include "fstrm-private.h"

struct fstrm_control {
	fstrm_control_type	type;
	uint8_t			*content_type;
	size_t			len_content_type;
};

const char *
fstrm_control_type_to_str(fstrm_control_type type)
{
	switch (type) {
	case FSTRM_CONTROL_ACCEPT:
		return "FSTRM_CONTROL_ACCEPT";
	case FSTRM_CONTROL_START:
		return "FSTRM_CONTROL_START";
	case FSTRM_CONTROL_STOP:
		return "FSTRM_CONTROL_STOP";
	default:
		return "FSTRM_CONTROL_UNKNOWN";
	}
}

const char *
fstrm_control_field_type_to_str(fstrm_control_field f_type)
{
	switch (f_type) {
	case FSTRM_CONTROL_FIELD_CONTENT_TYPE:
		return "FSTRM_CONTROL_FIELD_CONTENT_TYPE";
	default:
		return "FSTRM_CONTROL_FIELD_UNKNOWN";
	}
}

struct fstrm_control *
fstrm_control_init(void)
{
	struct fstrm_control *c;
	c = my_calloc(1, sizeof(*c));
	return c;
}

void
fstrm_control_destroy(struct fstrm_control **c)
{
	if (*c != NULL) {
		fstrm_control_reset(*c);
		my_free(*c);
	}
}

void
fstrm_control_reset(struct fstrm_control *c)
{
	my_free(c->content_type);
	memset(c, 0, sizeof(*c));
}

fstrm_res
fstrm_control_get_type(struct fstrm_control *c, fstrm_control_type *type)
{
	switch (c->type) {
	case FSTRM_CONTROL_ACCEPT:	/* FALLTHROUGH */
	case FSTRM_CONTROL_START:	/* FALLTHROUGH */
	case FSTRM_CONTROL_STOP:
		*type = c->type;
		return FSTRM_RES_SUCCESS;
	default:
		return FSTRM_RES_FAILURE;
	}
}

fstrm_res
fstrm_control_set_type(struct fstrm_control *c, fstrm_control_type type)
{
	switch (type) {
	case FSTRM_CONTROL_ACCEPT:	/* FALLTHROUGH */
	case FSTRM_CONTROL_START:	/* FALLTHROUGH */
	case FSTRM_CONTROL_STOP:
		c->type = type;
		return FSTRM_RES_SUCCESS;
	default:
		return FSTRM_RES_FAILURE;
	}
}

fstrm_res
fstrm_control_get_field_content_type(struct fstrm_control *c,
				     const uint8_t **content_type,
				     size_t *len_content_type)
{
	if (c->content_type != NULL) {
		*content_type = c->content_type;
		*len_content_type = c->len_content_type;
		return FSTRM_RES_SUCCESS;
	} else {
		return FSTRM_RES_FAILURE;
	}
}

fstrm_res
fstrm_control_set_field_content_type(struct fstrm_control *c,
				     const uint8_t *content_type,
				     size_t len_content_type)
{
	if (len_content_type > FSTRM_MAX_CONTROL_FIELD_CONTENT_TYPE_LENGTH)
		return FSTRM_RES_FAILURE;
	if (c->content_type != NULL)
		my_free(c->content_type);
	c->len_content_type = len_content_type;
	c->content_type = my_malloc(len_content_type);
	memmove(c->content_type, content_type, len_content_type);
	return FSTRM_RES_SUCCESS;
}

fstrm_res
fstrm_control_decode(struct fstrm_control *c,
		     const void *control_frame,
		     size_t len_control_frame,
		     const uint32_t flags)
{
	const uint8_t *buf = control_frame;
	size_t len = len_control_frame;
	uint32_t val;

	fstrm_control_reset(c);

	if (flags & FSTRM_CONTROL_FLAG_WITH_HEADER) {
		/* Read the outer frame length. */
		if (!fs_load_be32(&buf, &len, &val))
			return FSTRM_RES_FAILURE;

		/* The outer frame length must be zero, since this is a control frame. */
		if (val != 0)
			return FSTRM_RES_FAILURE;
		
		/* Read the control frame length. */
		if (!fs_load_be32(&buf, &len, &val))
			return FSTRM_RES_FAILURE;

		/* Enforce maximum control frame size. */
		if (val > FSTRM_MAX_CONTROL_FRAME_LENGTH)
			return FSTRM_RES_FAILURE;

		/*
		 * Require that the control frame length matches the number of
		 * bytes remaining in 'buf'.
		 */
		if (val != len)
			return FSTRM_RES_FAILURE;
	} else {
		/* Enforce maximum control frame size. */
		if (len_control_frame > FSTRM_MAX_CONTROL_FRAME_LENGTH)
			return FSTRM_RES_FAILURE;
	}

	/* Read the control frame type. */
	if (!fs_load_be32(&buf, &len, &val))
		return FSTRM_RES_FAILURE;
	switch (val) {
	case FSTRM_CONTROL_ACCEPT:	/* FALLTHROUGH */
	case FSTRM_CONTROL_START:	/* FALLTHROUGH */
	case FSTRM_CONTROL_STOP:
		c->type = (fstrm_control_type) val;
		break;
	default:
		return FSTRM_RES_FAILURE;
	}

	/* Read any control frame fields. */
	while (len > 0) {
		/* Read the control frame field type. */
		if (!fs_load_be32(&buf, &len, &val))
			return FSTRM_RES_FAILURE;

		switch (val) {
		case FSTRM_CONTROL_FIELD_CONTENT_TYPE: {
			/* Read the length of the "Content Type" payload. */
			if (!fs_load_be32(&buf, &len, &val))
				return FSTRM_RES_FAILURE;
			c->len_content_type = val;

			/*
			 * Sanity check the length field. It cannot be larger
			 * than 'len', the number of bytes remaining in 'buf'.
			 */
			if (c->len_content_type > len)
				return FSTRM_RES_FAILURE;

			/* Enforce limit on "Content Type" payload length. */
			if (c->len_content_type > FSTRM_MAX_CONTROL_FIELD_CONTENT_TYPE_LENGTH)
				return FSTRM_RES_FAILURE;

			/* Read the "Content Type" payload. */
			c->content_type = my_malloc(c->len_content_type);
			if (!fs_load_bytes(c->content_type, c->len_content_type, &buf, &len))
			{
				return FSTRM_RES_FAILURE;
			}

			break;
		}
		default:
			return FSTRM_RES_FAILURE;
		}
	}

	return FSTRM_RES_SUCCESS;
}

fstrm_res
fstrm_control_encoded_size(struct fstrm_control *c,
			   size_t *len_control_frame,
			   const uint32_t flags)
{
	size_t len = 0;
	
	if (flags & FSTRM_CONTROL_FLAG_WITH_HEADER) {
		/* Escape: 32-bit BE integer. */
		len += sizeof(uint32_t);

		/* Frame length: 32-bit BE integer. */
		len += sizeof(uint32_t);
	}

	/* Control type: 32-bit BE integer. */
	len += sizeof(uint32_t);

	if (c->content_type != NULL) {
		/* FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer. */
		len += sizeof(uint32_t);

		/* Length of the "Content Type" string: 32-bit BE integer. */
		len += sizeof(uint32_t);

		/* Enforce limit on "Content Type" payload length. */
		if (c->len_content_type > FSTRM_MAX_CONTROL_FIELD_CONTENT_TYPE_LENGTH)
			return FSTRM_RES_FAILURE;

		/* The "Content Type" payload. */
		len += c->len_content_type;
	}

	/* Sanity check. */
	if (len > FSTRM_MAX_CONTROL_FRAME_LENGTH)
		return FSTRM_RES_FAILURE;

	*len_control_frame = len;
	return FSTRM_RES_SUCCESS;
}

fstrm_res
fstrm_control_encode(struct fstrm_control *c,
		     void *control_frame,
		     size_t *len_control_frame,
		     const uint32_t flags)
{
	fstrm_res res;
	size_t encoded_size;

	/* Calculate the size of the control frame. */
	res = fstrm_control_encoded_size(c, &encoded_size, flags);
	if (res != FSTRM_RES_SUCCESS)
		return res;

	/*
	 * The caller must have provided a large enough buffer to serialize the
	 * control frame.
	 */
	if (*len_control_frame < encoded_size)
		return FSTRM_RES_FAILURE;

	/*
	 * Now actually serialize the control frame.
	 */
	size_t len = encoded_size;
	uint8_t *buf = control_frame;

	if (flags & FSTRM_CONTROL_FLAG_WITH_HEADER) {
		/* Escape: 32-bit BE integer. Zero. */
		if (!fs_store_be32(&buf, &len, 0))
			return FSTRM_RES_FAILURE;

		/*
		 * Frame length: 32-bit BE integer.
		 *
		 * This does not include the length of the escape frame or the length
		 * of the frame length field itself, so subtract 2*4 bytes from the
		 * total length.
		 */
		if (!fs_store_be32(&buf, &len, encoded_size - 2 * sizeof(uint32_t)))
			return FSTRM_RES_FAILURE;
	}

	/* Control type: 32-bit BE integer. */
	if (!fs_store_be32(&buf, &len, c->type))
		return FSTRM_RES_FAILURE;

	if (c->content_type != NULL) {
		/* FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer. */
		if (!fs_store_be32(&buf, &len, FSTRM_CONTROL_FIELD_CONTENT_TYPE))
			return FSTRM_RES_FAILURE;

		/* Length of the "Content Type" payload: 32-bit BE integer. */
		if (!fs_store_be32(&buf, &len, c->len_content_type))
			return FSTRM_RES_FAILURE;

		/* The "Content Type" string itself. */
		if (!fs_store_bytes(&buf, &len, c->content_type, c->len_content_type))
			return FSTRM_RES_FAILURE;
	}

	*len_control_frame = encoded_size;
	return FSTRM_RES_SUCCESS;
}
