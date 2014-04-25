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
#include "libmy/my_memory_barrier.h"
#include "libmy/my_queue.h"
#include "libmy/vector.h"

#if defined(__GNUC__)
# define likely(x)		__builtin_expect(!!(x), 1)
# define unlikely(x)		__builtin_expect(!!(x), 0)
# define warn_unused_result	__attribute__ ((warn_unused_result))
#else
# define likely(x)
# define unlikely(x)
# define warn_unused_result
#endif

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif

#ifndef IOV_MAX
# define IOV_MAX 1024
#endif

/* fs_buf, fs_bufvec */

typedef struct {
	size_t		len;
	uint8_t		*data;
} fs_buf;

VECTOR_GENERATE(fs_bufvec, fs_buf);

/* buffer helpers */

warn_unused_result
static inline bool
fs_load_be32(const uint8_t **buf, size_t *len, uint32_t *val)
{
	uint32_t be32_val;

	if (*len < sizeof(be32_val))
		return false;
	memmove(&be32_val, *buf, sizeof(be32_val));
	*val = ntohl(be32_val);
	*len -= sizeof(be32_val);
	*buf += sizeof(be32_val);
	return true;
}

warn_unused_result
static inline bool
fs_store_be32(uint8_t **buf, size_t *len, const uint32_t val)
{
	uint32_t be32_val;

	be32_val = ntohl(val);
	if (*len < sizeof(be32_val))
		return false;
	memmove(*buf, &be32_val, sizeof(be32_val));
	*len -= sizeof(be32_val);
	*buf += sizeof(be32_val);
	return true;
}

warn_unused_result
static inline bool
fs_load_bytes(uint8_t *bytes, size_t len_bytes,
	      const uint8_t **buf, size_t *len)
{
	if (*len < len_bytes)
		return false;
	memmove(bytes, *buf, len_bytes);
	*len -= len_bytes;
	*buf += len_bytes;
	return true;
}

warn_unused_result
static inline bool
fs_store_bytes(uint8_t **buf, size_t *len,
	       const uint8_t *bytes, size_t len_bytes)
{
	if (*len < len_bytes)
		return false;
	memmove(*buf, bytes, len_bytes);
	*len -= len_bytes;
	*buf += len_bytes;
	return true;
}

/* writer */

struct fstrm_writer {
	fstrm_writer_create_func	create;
	fstrm_writer_destroy_func	destroy;
	fstrm_writer_open_func		open;
	fstrm_writer_close_func		close;
	fstrm_writer_read_func		read_control;
	fstrm_writer_write_func		write_control;
	fstrm_writer_write_func		write_data;
};

/* options */

struct fstrm_io_options {
	void			*content_type;
	size_t			len_content_type;

	unsigned		buffer_hint;
	unsigned		flush_timeout;
	unsigned		iovec_size;
	unsigned		num_queues;
	unsigned		queue_length;
	unsigned		queue_notify_threshold;
	unsigned		reconnect_interval;

	struct fstrm_writer	*writer;
	const void		*writer_options;

	fstrm_queue_model	queue_model;
};

void fs_io_options_dup(struct fstrm_io_options *, const struct fstrm_io_options *);

bool fs_io_options_validate(const struct fstrm_io_options *, char **errstr_out);

/* time */

bool fs_get_best_monotonic_clock_gettime(clockid_t *);

bool fs_get_best_monotonic_clock_pthread(clockid_t *);

bool fs_get_best_monotonic_clocks(clockid_t *clkid_gettime,
				  clockid_t *clkid_pthread,
				  char **errstr_out);

int fs_pthread_cond_timedwait(clockid_t, pthread_cond_t *, pthread_mutex_t *, unsigned);

/* queue */

#ifdef MY_HAVE_MEMORY_BARRIERS
extern const struct my_queue_ops my_queue_mb_ops;
#endif

extern const struct my_queue_ops my_queue_mutex_ops;

#endif /* FSTRM_PRIVATE_H */
