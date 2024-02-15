#ifndef MY_READ_BYTES_H
#define MY_READ_BYTES_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/poll.h>

typedef bool (*can_continue_func)(int fd, void *clos);

typedef enum {
	poll_success = 0,
	poll_timeout = 1,
	poll_error = 2,
	poll_hup = 3,
} poll_res;

static inline poll_res
do_poll(int fd, int events, int timeout)
{
	int res = 0;
	struct pollfd fds[1];

	fds[0].fd = fd;
	fds[0].events = events;
	res = poll(fds, 1, timeout);

	if (res < 0)
		return poll_error;

	if (res == 0)
		return poll_timeout;

	if ((fds[0].revents & POLLRDHUP) ||
		(!(events & POLLIN) && (fds[0].revents & POLLHUP)) ||
		(fds[0].revents & POLLNVAL)) {
		return poll_hup;
	}

	if (fds[0].revents & events)
		return poll_success;

	/* It shall never reach this */
	assert(false);
	return poll_error;
}

static inline bool
read_bytes_ex(int fd, uint8_t *buf, size_t bytes_needed, can_continue_func fn, void *clos)
{
	while (bytes_needed > 0) {
		ssize_t bytes_read;
		if (!fn(fd, clos))
			return false;
		bytes_read = read(fd, buf, bytes_needed);
		if (bytes_read == -1 && errno == EINTR)
			continue;
		else if (bytes_read <= 0)
			return false;
		bytes_needed -= bytes_read;
		buf += bytes_read;
	}
	return true;
}

static inline bool
read_bytes(int fd, uint8_t *buf, size_t bytes_needed)
{
	while (bytes_needed > 0) {
		ssize_t bytes_read;

		bytes_read = read(fd, buf, bytes_needed);
		if (bytes_read == -1 && errno == EINTR)
			continue;
		else if (bytes_read <= 0)
			return false;
		bytes_needed -= bytes_read;
		buf += bytes_read;
	}
	return true;
}

#endif /* MY_READ_BYTES_H */
