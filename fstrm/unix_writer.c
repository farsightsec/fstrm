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
#include <fcntl.h>
#include <unistd.h>

#include "fstrm-private.h"

#define FS_UNIX_WRITER_OPTIONS_MAGIC	0xAC681DE98E858D12

struct fstrm_unix_writer_options {
	uint64_t		magic;
	char			*socket_path;
};

struct fs_unix_writer {
	bool			connected;
	int			fd;
	struct sockaddr_un	sa;
};

static fstrm_res
fs_unix_writer_open(void *data)
{
	struct fs_unix_writer *w = data;

	/* Nothing to do if the socket is already connected. */
	if (w->connected)
		return fstrm_res_success;

	/* Open an AF_UNIX socket. Request socket close-on-exec if available. */
#if defined(SOCK_CLOEXEC)
	w->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (w->fd < 0 && errno == EINVAL)
		w->fd = socket(AF_UNIX, SOCK_STREAM, 0);
#else
	w->fd = socket(AF_UNIX, SOCK_STREAM, 0);
#endif
	if (w->fd < 0)
		return fstrm_res_failure;

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

#if defined(SO_NOSIGPIPE)
	/*
	 * Ugh, no signals, please!
	 *
	 * https://lwn.net/Articles/414618/
	 * [ Ghosts of Unix past, part 3: Unfixable designs ]
	 */
	static const int on = 1;
	if (setsockopt(w->fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0) {
		close(w->fd);
		return fstrm_res_failure;
	}
#endif

	/* Connect the AF_UNIX socket. */
	if (connect(w->fd, (struct sockaddr *) &w->sa, sizeof(w->sa)) < 0) {
		close(w->fd);
		return fstrm_res_failure;
	}

	w->connected = true;
	return fstrm_res_success;
}

static fstrm_res
fs_unix_writer_close(void *data)
{
	struct fs_unix_writer *w = data;

	if (w->connected)
		close(w->fd);
	w->connected = false;

	return fstrm_res_success;
}

static fstrm_res
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

	if (likely(w->connected)) {
		for (;;) {
			do {
				written = sendmsg(w->fd, &msg, MSG_NOSIGNAL);
			} while (written == -1 && errno == EINTR);
			if (written == -1)
				return fstrm_res_failure;
			if (cur == 0 && written == (ssize_t) nbytes)
				return fstrm_res_success;

			while (written >= (ssize_t) msg.msg_iov[cur].iov_len)
			       written -= msg.msg_iov[cur++].iov_len;

			if (cur == iovcnt)
				return fstrm_res_success;

			msg.msg_iov[cur].iov_base = (void *)
				((char *) msg.msg_iov[cur].iov_base + written);
			msg.msg_iov[cur].iov_len -= written;
		}
	} else {
		return fstrm_res_failure;
	}

	return fstrm_res_success;
}

static fstrm_res
fs_unix_writer_create(struct fstrm_io *io __attribute__((__unused__)),
		      const struct fstrm_writer_options *opt,
		      void **data)
{
	struct fs_unix_writer *w;
	const struct fstrm_unix_writer_options *wopt = 
		(const struct fstrm_unix_writer_options *) opt;

	if (wopt->magic != FS_UNIX_WRITER_OPTIONS_MAGIC)
		return fstrm_res_failure;

	if (wopt->socket_path == NULL)
		return fstrm_res_failure;

	if (strlen(wopt->socket_path) + 1 > sizeof(w->sa.sun_path))
		return fstrm_res_failure;

	w = my_calloc(1, sizeof(*w));
	w->sa.sun_family = AF_UNIX;
	strncpy(w->sa.sun_path, wopt->socket_path, sizeof(w->sa.sun_path) - 1);

	(void) fs_unix_writer_open(w);

	*data = w;
	return fstrm_res_success;
}

static fstrm_res
fs_unix_writer_destroy(void *data)
{
	struct fs_unix_writer *w = data;
	(void) fs_unix_writer_close(w);
	my_free(w);
	return fstrm_res_success;
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
		my_free((*wopt)->socket_path);
		my_free(*wopt);
	}
}

void
fstrm_unix_writer_options_set_socket_path(
	struct fstrm_unix_writer_options *wopt,
	const char *socket_path)
{
	if (socket_path != NULL) {
		if (wopt->socket_path != NULL)
			my_free(wopt->socket_path);
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
	.write_control =
		fs_unix_writer_write,
	.write_data =
		fs_unix_writer_write,
};
const struct fstrm_writer *fstrm_unix_writer = &fs_writer_impl_unix;
