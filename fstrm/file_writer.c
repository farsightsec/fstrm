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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "fstrm-private.h"

#define FS_FILE_WRITER_OPTIONS_MAGIC	0xE1BFC3A08441E981

struct fstrm_file_writer_options {
	uint64_t		magic;
	char			*file_path;
};

struct fs_file_writer {
	bool			opened;
	int			fd;
	char			*file_path;
};

static fstrm_res
fs_file_writer_open(void *data)
{
	struct fs_file_writer *w = data;

	/* Nothing to do if the file descriptor is already opened. */
	if (w->opened)
		return FSTRM_RES_SUCCESS;

	/* Open the file descriptor. Request close-on-exec if available. */
	int open_flags = O_CREAT | O_WRONLY | O_TRUNC;
#if defined(O_CLOEXEC)
	open_flags |= O_CLOEXEC;
#endif
	w->fd = open(w->file_path, open_flags,
		     S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	if (w->fd < 0)
		return FSTRM_RES_FAILURE;

	/*
	 * Request close-on-exec if available. There is nothing that can be done
	 * if the F_SETFD call to fcntl() fails, so don't bother checking the
	 * return value.
	 *
	 * https://lwn.net/Articles/412131/
	 * [ Ghosts of Unix past, part 2: Conflated designs ]
	 */
#if defined(FD_CLOEXEC)
	int flags = fcntl(w->fd, F_GETFD, 0);
	if (flags != -1) {
		flags |= FD_CLOEXEC;
		(void) fcntl(w->fd, F_SETFD, flags);
	}
#endif

	w->opened = true;
	return FSTRM_RES_SUCCESS;
}

static fstrm_res
fs_file_writer_close(void *data)
{
	struct fs_file_writer *w = data;

	if (w->opened)
		close(w->fd);
	w->opened = false;

	return FSTRM_RES_SUCCESS;
}

static fstrm_res
fs_file_writer_write(void *data,
		     struct iovec *iov, int iovcnt,
		     unsigned nbytes)
{
	struct fs_file_writer *w = data;
	ssize_t written = 0;
	int cur = 0;

	if (likely(w->opened)) {
		for (;;) {
			do {
				written = writev(w->fd, iov, iovcnt);
			} while (written == -1 && errno == EINTR);
			if (written == -1)
				return FSTRM_RES_FAILURE;
			if (cur == 0 && written == (ssize_t) nbytes)
				return FSTRM_RES_SUCCESS;

			while (written >= (ssize_t) iov[cur].iov_len)
			       written -= iov[cur++].iov_len;

			if (cur == iovcnt)
				return FSTRM_RES_SUCCESS;

			iov[cur].iov_base = (void *)
				((char *) iov[cur].iov_base + written);
			iov[cur].iov_len -= written;
		}
	} else {
		return FSTRM_RES_FAILURE;
	}

	return FSTRM_RES_SUCCESS;
}

static fstrm_res
fs_file_writer_create(struct fstrm_io *io __attribute__((__unused__)),
		      const struct fstrm_writer_options *opt,
		      void **data)
{
	struct fs_file_writer *w;
	const struct fstrm_file_writer_options *wopt = 
		(const struct fstrm_file_writer_options *) opt;

	if (wopt->magic != FS_FILE_WRITER_OPTIONS_MAGIC)
		return FSTRM_RES_FAILURE;

	if (wopt->file_path == NULL)
		return FSTRM_RES_FAILURE;

	w = my_calloc(1, sizeof(*w));
	w->file_path = my_strdup(wopt->file_path);

	(void) fs_file_writer_open(w);

	*data = w;
	return FSTRM_RES_SUCCESS;
}

static fstrm_res
fs_file_writer_destroy(void *data)
{
	struct fs_file_writer *w = data;
	(void) fs_file_writer_close(w);
	my_free(w->file_path);
	my_free(w);
	return FSTRM_RES_SUCCESS;
}

struct fstrm_file_writer_options *
fstrm_file_writer_options_init(void)
{
	struct fstrm_file_writer_options *wopt;
	wopt = my_calloc(1, sizeof(*wopt));
	wopt->magic = FS_FILE_WRITER_OPTIONS_MAGIC;
	return wopt;
}

void
fstrm_file_writer_options_destroy(struct fstrm_file_writer_options **wopt)
{
	if (*wopt != NULL) {
		my_free((*wopt)->file_path);
		my_free(*wopt);
	}
}

void
fstrm_file_writer_options_set_file_path(
	struct fstrm_file_writer_options *wopt,
	const char *file_path)
{
	if (file_path != NULL) {
		if (wopt->file_path != NULL)
			my_free(wopt->file_path);
		wopt->file_path = my_strdup(file_path);
	}
}

static const struct fstrm_writer fs_writer_impl_file = {
	.create =
		fs_file_writer_create,
	.destroy =
		fs_file_writer_destroy,
	.open =
		fs_file_writer_open,
	.close =
		fs_file_writer_close,
	.write_control =
		fs_file_writer_write,
	.write_data =
		fs_file_writer_write,
};
const struct fstrm_writer *fstrm_file_writer = &fs_writer_impl_file;
