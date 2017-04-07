/*
 * Copyright (c) 2014, 2016 by Farsight Security, Inc.
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

struct fstrm_file_options {
	char	*file_path;
};

struct fstrm__file {
	FILE	*fp;
	char	*file_path;
	char	file_mode[2];
};

struct fstrm_file_options *
fstrm_file_options_init(void)
{
	return my_calloc(1, sizeof(struct fstrm_file_options));
}

void
fstrm_file_options_destroy(struct fstrm_file_options **fopt)
{
	if (*fopt != NULL) {
		my_free((*fopt)->file_path);
		my_free(*fopt);
	}
}

void
fstrm_file_options_set_file_path(struct fstrm_file_options *fopt,
				 const char *file_path)
{
	my_free(fopt->file_path);
	if (file_path != NULL)
		fopt->file_path = my_strdup(file_path);
}

static fstrm_res
fstrm__file_op_open(void *obj)
{
	struct fstrm__file *f = obj;
	if (f->fp == NULL && f->file_path != NULL) {
		if (!strcmp(f->file_path, "-"))
			f->fp = f->file_mode[0] == 'r' ? stdin : stdout;
		else
			f->fp = fopen(f->file_path, f->file_mode);
		if (f->fp == NULL)
			return fstrm_res_failure;
		return fstrm_res_success;
	}
	return fstrm_res_failure;
}

static fstrm_res
fstrm__file_op_close(void *obj)
{
	struct fstrm__file *f = obj;
	if (f->fp != NULL) {
		FILE *fp = f->fp;
		f->fp = NULL;
		if (fclose(fp) != 0)
			return fstrm_res_failure;
		return fstrm_res_success;
	}
	return fstrm_res_failure;
}

static fstrm_res
fstrm__file_op_read(void *obj, void *data, size_t count)
{
	struct fstrm__file *f = obj;
	if (likely(f->fp != NULL)) {
		if (likely(fread(data, count, 1, f->fp) == 1)) {
			return fstrm_res_success;
		} else {
			if (ferror(f->fp))
				return fstrm_res_failure;
			if (feof(f->fp))
				return fstrm_res_stop;
		}
	}
	return fstrm_res_failure;
}

static fstrm_res
fstrm__file_op_write(void *obj, const struct iovec *iov, int iovcnt) {
	struct fstrm__file *f = obj;
	if (unlikely(f->fp == NULL))
		return fstrm_res_failure;
	for (int idx = 0; idx < iovcnt; idx++) {
		if (unlikely(fwrite(iov[idx].iov_base, iov[idx].iov_len, 1, f->fp) != 1)) {
			(void)fstrm__file_op_close(f);
			return fstrm_res_failure;
		}
	}
	return fstrm_res_success;
}

static fstrm_res
fstrm__file_op_destroy(void *obj)
{
	struct fstrm__file *f = obj;
	my_free(f->file_path);
	my_free(f);
	return fstrm_res_success;
}

static struct fstrm_rdwr *
fstrm__file_init(const struct fstrm_file_options *fopt, const char file_mode)
{
	struct fstrm__file *f;
	struct fstrm_rdwr *rdwr;

	if (fopt->file_path == NULL)
		return NULL;

	f = my_calloc(1, sizeof(*f));
	f->file_path = my_strdup(fopt->file_path);
	f->file_mode[0] = file_mode;
	f->file_mode[1] = '\0';

	rdwr = fstrm_rdwr_init(f);
	fstrm_rdwr_set_destroy(rdwr, fstrm__file_op_destroy);
	fstrm_rdwr_set_open(rdwr, fstrm__file_op_open);
	fstrm_rdwr_set_close(rdwr, fstrm__file_op_close);
	return rdwr;
}

struct fstrm_reader *
fstrm_file_reader_init(const struct fstrm_file_options *fopt,
		       const struct fstrm_reader_options *ropt)
{
	struct fstrm_rdwr *rdwr = fstrm__file_init(fopt, 'r');
	if (!rdwr)
		return NULL;
	fstrm_rdwr_set_read(rdwr, fstrm__file_op_read);
	return fstrm_reader_init(ropt, &rdwr);
}

struct fstrm_writer *
fstrm_file_writer_init(const struct fstrm_file_options *fopt,
		       const struct fstrm_writer_options *wopt)
{
	struct fstrm_rdwr *rdwr = fstrm__file_init(fopt, 'w');
	if (!rdwr)
		return NULL;
	fstrm_rdwr_set_write(rdwr, fstrm__file_op_write);
	return fstrm_writer_init(wopt, &rdwr);
}
