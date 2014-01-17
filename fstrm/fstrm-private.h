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

#ifndef FSTRM_PRIVATE_H
#define FSTRM_PRIVATE_H

#include <arpa/inet.h>
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fstrm.h"

#include "libmy/my_alloc.h"
#include "libmy/my_queue.h"

#if defined(__GNUC__)
# define likely(x)      __builtin_expect(!!(x), 1)
# define unlikely(x)    __builtin_expect(!!(x), 0)
#else
# define likely(x)
# define unlikely(x)
#endif

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif

#ifndef IOV_MAX
# define IOV_MAX 1024
#endif

/* writer */

struct fstrm_writer {
	int	(*create)
			(const struct fstrm_writer_options *, void **data);
	int	(*destroy)
			(void *data);
	int	(*connect)
			(void *data);
	int	(*disconnect)
			(void *data);
	int	(*is_connected)
			(void *data);
	int	(*writev)
			(void *data, struct iovec *iov, int iovcnt, unsigned nbytes);
};

/* options */

struct fstrm_io_options {
	void		*content_type;
	size_t		len_content_type;

	unsigned	buffer_hint;
	unsigned	flush_timeout;
	unsigned	iovec_size;
	unsigned	num_queues;
	unsigned	queue_length;
	unsigned	queue_notify_threshold;
	unsigned	reconnect_interval;

	struct fstrm_writer			*writer;
	const void				*writer_options;
};

bool fs_validate_io_options(const struct fstrm_io_options *, char **errstr_out);

/* time */

bool fs_get_best_monotonic_clock_gettime(clockid_t *);

bool fs_get_best_monotonic_clock_pthread(clockid_t *);

bool fs_get_best_monotonic_clocks(clockid_t *clkid_gettime,
				  clockid_t *clkid_pthread,
				  char **errstr_out);

int fs_pthread_cond_timedwait(clockid_t, pthread_cond_t *, pthread_mutex_t *, unsigned);

#endif /* FSTRM_PRIVATE_H */
