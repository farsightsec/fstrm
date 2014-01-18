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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "fstrm-private.h"

#define FS_UNIX_WRITER_OPTIONS_MAGIC	0xAC681DE98E858D12

struct fstrm_unix_writer_options {
	uint64_t		magic;
	char			*socket_path;
};

struct fs_unix_writer {
	bool			connected;
	bool			fd_opened;
	int			fd;
	struct sockaddr_un	sa;
};

static int
fs_unix_writer_open(void *data)
{
	struct fs_unix_writer *w = data;

	if (w->fd_opened) {
		close(w->fd);
		w->fd_opened = false;
		w->connected = false;
	}

	w->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (w->fd < 0)
		return 1; /* failure */
	w->fd_opened = true;

#if defined(SO_NOSIGPIPE)
	static const int on = 1;
	if (setsockopt(w->fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0) {
		close(w->fd);
		w->fd_opened = false;
		return 1; /* failure */
	}
#endif

	if (connect(w->fd, (struct sockaddr *) &w->sa, sizeof(w->sa)) < 0)
		return 1; /* failure */
	w->connected = true;

	return 0; /* success */
}

static int
fs_unix_writer_close(void *data)
{
	struct fs_unix_writer *w = data;

	if (w->fd_opened) {
		close(w->fd);
		w->fd_opened = false;
		w->connected = false;
	}

	return 0; /* success */
}

static int
fs_unix_writer_is_opened(void *data)
{
	struct fs_unix_writer *w = data;

	if (w->connected)
		return 1;
	return 0;
}

static int
fs_unix_writer_write(void *data,
		     struct iovec *iov, int iovcnt,
		     unsigned nbytes)
{
	struct fs_unix_writer *w = data;
	ssize_t written = 0;
	int cur = 0;
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = iovcnt,
	};

	for (;;) {
		do {
			written = sendmsg(w->fd, &msg, MSG_NOSIGNAL);
		} while (written == -1 && errno == EINTR);
		if (written == -1)
			return 1; /* failure */
		if (cur == 0 && written == (ssize_t) nbytes)
			return 0; /* success */

		while (written >= (ssize_t) msg.msg_iov[cur].iov_len)
		       written -= msg.msg_iov[cur++].iov_len;

		if (cur == iovcnt)
			return 0; /* success */

		msg.msg_iov[cur].iov_base = (void *)
			((char *) msg.msg_iov[cur].iov_base + written);
		msg.msg_iov[cur].iov_len -= written;
	}

	return 0; /* success */
}

static int
fs_unix_writer_create(const struct fstrm_writer_options *opt, void **data)
{
	struct fs_unix_writer *w;
	const struct fstrm_unix_writer_options *wopt = 
		(const struct fstrm_unix_writer_options *) opt;

	if (wopt->magic != FS_UNIX_WRITER_OPTIONS_MAGIC)
		return 1; /* failure */

	if (wopt->socket_path == NULL)
		return 1; /* failure */

	if (strlen(wopt->socket_path) + 1 > sizeof(w->sa.sun_path))
		return 1; /* failure */

	w = my_calloc(1, sizeof(*w));
	w->sa.sun_family = AF_UNIX;
	strncpy(w->sa.sun_path, wopt->socket_path, sizeof(w->sa.sun_path) - 1);

	(void) fs_unix_writer_open(w);

	*data = w;
	return 0; /* success */
}

static int
fs_unix_writer_destroy(void *data)
{
	struct fs_unix_writer *w = data;
	(void) fs_unix_writer_close(w);
	free(w);
	return 0; /* success */
}

struct fstrm_unix_writer_options *
fstrm_unix_writer_options_init(void)
{
	struct fstrm_unix_writer_options *wopt;
	wopt = my_calloc(1, sizeof(*wopt));
	wopt->magic = FS_UNIX_WRITER_OPTIONS_MAGIC;
	return wopt;
}

void
fstrm_unix_writer_options_destroy(struct fstrm_unix_writer_options **wopt)
{
	if (*wopt != NULL) {
		free((*wopt)->socket_path);
		free(*wopt);
		*wopt = NULL;
	}
}

void
fstrm_unix_writer_options_set_socket_path(
	struct fstrm_unix_writer_options *wopt,
	const char *socket_path)
{
	if (socket_path != NULL) {
		if (wopt->socket_path != NULL)
			free(wopt->socket_path);
		wopt->socket_path = my_strdup(socket_path);
	}
}

static const struct fstrm_writer fs_writer_impl_unix = {
	.create =
		fs_unix_writer_create,
	.destroy =
		fs_unix_writer_destroy,
	.open =
		fs_unix_writer_open,
	.close =
		fs_unix_writer_close,
	.is_opened =
		fs_unix_writer_is_opened,
	.write_control =
		fs_unix_writer_write,
	.write_data =
		fs_unix_writer_write,
};
const struct fstrm_writer *fstrm_unix_writer = &fs_writer_impl_unix;
