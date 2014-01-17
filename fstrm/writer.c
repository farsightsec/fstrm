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
fstrm_writer_set_create_func(struct fstrm_writer *w,
			     fstrm_writer_create_func create)
{
	w->create = create;
}

void
fstrm_writer_set_destroy_func(struct fstrm_writer *w,
			      fstrm_writer_destroy_func destroy)
{
	w->destroy = destroy;
}

void
fstrm_writer_set_open_func(struct fstrm_writer *w,
			   fstrm_writer_open_func open)
{
	w->open = open;
}

void
fstrm_writer_set_close_func(struct fstrm_writer *w,
			    fstrm_writer_close_func close)
{
	w->close = close;
}

void
fstrm_writer_set_is_opened_func(struct fstrm_writer *w,
				fstrm_writer_is_opened_func is_opened)
{
	w->is_opened = is_opened;
}

void
fstrm_writer_set_writev_func(struct fstrm_writer *w,
			     fstrm_writer_writev_func writev)
{
	w->writev = writev;
}
