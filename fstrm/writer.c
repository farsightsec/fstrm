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

struct fstrm_writer *
fstrm_writer_init(void)
{
	struct fstrm_writer *w;
	w = my_calloc(1, sizeof(*w));
	return w;
}

void
fstrm_writer_destroy(struct fstrm_writer **w)
{
	if (*w != NULL) {
		free(*w);
		*w = NULL;
	}
}

void
fstrm_writer_set_create(struct fstrm_writer *w,
			fstrm_writer_create_func w_create)
{
	w->create = w_create;
}

void
fstrm_writer_set_destroy(struct fstrm_writer *w,
			 fstrm_writer_destroy_func w_destroy)
{
	w->destroy = w_destroy;
}

void
fstrm_writer_set_open(struct fstrm_writer *w,
		      fstrm_writer_open_func w_open)
{
	w->open = w_open;
}

void
fstrm_writer_set_close(struct fstrm_writer *w,
		       fstrm_writer_close_func w_close)
{
	w->close = w_close;
}

void
fstrm_writer_set_write_control(struct fstrm_writer *w,
			       fstrm_writer_write_func w_write_control)
{
	w->write_control = w_write_control;
}

void
fstrm_writer_set_write_data(struct fstrm_writer *w,
			    fstrm_writer_write_func w_write_data)
{
	w->write_data = w_write_data;
}
