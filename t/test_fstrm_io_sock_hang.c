#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>

#include <fstrm.h>

static const char *sock_addr = NULL;
static const char *address = NULL;
static const char *port = NULL;
static const char *header = "MASTER";
static int g_read_timeout = 1000;
static bool sigusr1 = false;
static int master = 0;
static int reader = 0;
static int writer = 0;

typedef int (*handler_func)(void);

typedef struct _fstrm_fd {
	int lfd, fd;
} fstrm_fd_t;


static void
debug(const char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	fprintf(stderr, "%s[%d]: ", header, getpid());
	vfprintf(stderr, msg, args);
	fprintf(stderr, "\n");
	fflush(stderr);
	va_end(args);
}

static void
usage(char *name)
{
	fprintf(stderr, "Usage: %s <SOCKET TYPE> <SOCKET PARAM> <TIMEOUT>\n", name);
	fprintf(stderr, "\n");
	fprintf(stderr, "\tSOCKET TYPE is 'tcp' or 'unix'.\n");
	fprintf(stderr, "\tFor SOCKET TYPE 'unix', SOCKET PARAMS should be a filesystem path.\n");
	fprintf(stderr, "\tFor SOCKET TYPE 'tcp', SOCKET PARAMS should be a socket address and port.\n");
	fprintf(stderr, "\tTIMEOUT is milliseconds as integer.\n");
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static void parse_args(int argc, char *argv[])
{
	if (argc < 2)
		usage(argv[0]);

	if (!strcmp(argv[1], "tcp")) {
		if (argc != 5)
			usage(argv[0]);
		address = argv[2];
		port = argv[3];
		g_read_timeout = atoi(argv[4]);
	} else if (!strcmp(argv[1], "unix")) {
		if (argc != 4)
			usage(argv[0]);
		sock_addr = argv[2];
		g_read_timeout = atoi(argv[3]);
	} else
		usage(argv[0]);
}

static struct fstrm_writer *
get_unix_writer(const char *path, int timeout)
{
	struct fstrm_writer *wr;
	struct fstrm_unix_writer_options *uwopt;

	uwopt = fstrm_unix_writer_options_init();
	fstrm_unix_writer_options_set_socket_path(uwopt, path);
	fstrm_unix_writer_options_set_read_timeout(uwopt, timeout);

	debug("Opening UNIX socket %s with timeout %d", path, timeout);
	wr = fstrm_unix_writer_init(uwopt, NULL);
	if (!wr)
		debug("Error: fstrm_unix_writer_init() failed.");

	fstrm_unix_writer_options_destroy(&uwopt);

	return wr;
}

static struct fstrm_writer *
get_tcp_writer(const char *addr, const char *cport, int timeout)
{
	struct fstrm_writer *wr;
	struct fstrm_tcp_writer_options *twopt;

	twopt = fstrm_tcp_writer_options_init();
	fstrm_tcp_writer_options_set_socket_address(twopt, addr);
	fstrm_tcp_writer_options_set_socket_port(twopt, cport);
	fstrm_tcp_writer_options_set_read_timeout(twopt, timeout);

	debug("Opening TCP socket %s:%s with timeout %d", addr, port, timeout);
	wr = fstrm_tcp_writer_init(twopt, NULL);
	if (!wr)
		debug("Error: fstrm_tcp_writer_init() failed.");

	fstrm_tcp_writer_options_destroy(&twopt);
	return wr;
}

static int
get_unix_socket(const char *socket_path)
{
	struct sockaddr_un sa;
	int fd;

	debug("Opening UNIX socket %s", socket_path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		abort();
	}

	if (remove(socket_path) == -1 && errno != ENOENT) {
		perror("remove");
		abort();
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, socket_path, sizeof(sa.sun_path) - 1);

	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
		perror("bind");
		abort();
	}

	if (listen(fd, 1) == -1) {
		perror("listen");
		abort();
	}

	return fd;
}

static int
get_tcp_socket(const char *socket_address, const char *cport)
{
	struct sockaddr_storage ss = {0};
	struct sockaddr_in *sai = (struct sockaddr_in *) &ss;
	struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) &ss;
	socklen_t ss_len = sizeof(ss);
	int fd, optval = 1;

	debug("Opening TCP socket %s:%s", socket_address, cport);

	if (inet_pton(AF_INET, socket_address, &sai->sin_addr) == 1) {
		ss.ss_family = AF_INET;
		sai->sin_port = htons(atoi(cport));
		ss_len = sizeof(*sai);
	} else if (inet_pton(AF_INET6, socket_address, &sai6->sin6_addr) == 1) {
		ss.ss_family = AF_INET6;
		sai6->sin6_port = htons(atoi(cport));
		ss_len = sizeof(*sai6);
	} else {
		perror("inet_pton");
		abort();
	}

	fd = socket(ss.ss_family, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		abort();
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
		perror("setsockopt");
		abort();
	}

	if (bind(fd, (struct sockaddr *) &ss, ss_len) == -1) {
		perror("bind");
		abort();
	}

	if (listen(fd, 1) == -1) {
		perror("listen");
		abort();
	}

	return fd;
}

static fstrm_res
reader_destroy(void *obj)
{
	fstrm_fd_t *ffd = (fstrm_fd_t *) obj;

	debug("reader_destroy %d", ffd->fd);
	return fstrm_res_success;
}

static fstrm_res
reader_open(void *obj)
{
	struct sockaddr_un c_addr = {0};
	fstrm_fd_t *ffd = (fstrm_fd_t *) obj;
	socklen_t c_len = sizeof(c_addr);

	debug("reader_open");
	ffd->lfd = (sock_addr ? get_unix_socket(sock_addr) : get_tcp_socket(address, port));
	assert(ffd->lfd);
	ffd->fd = accept(ffd->lfd, (struct sockaddr *) &c_addr, &c_len);
	assert(ffd->fd);
	return fstrm_res_success;
}

static fstrm_res
reader_close(void *obj)
{
	fstrm_fd_t *ffd = (fstrm_fd_t *) obj;

	debug("reader_close");
	if (ffd->fd > 0)
		close(ffd->fd);
	if (ffd->lfd > 0)
		close(ffd->lfd);
	ffd->fd = ffd->lfd = -1;

	return fstrm_res_success;
}

static fstrm_res
reader_write(void *obj, const struct iovec *iov, int iovcnt)
{
	int n;
	size_t total = 0;
	fstrm_fd_t *ffd = (fstrm_fd_t *) obj;

	debug("reader_write(%d)", ffd->fd);

	for (n = 0; n < iovcnt; n++) {
		ssize_t res;
		res = write(ffd->fd, iov[n].iov_base, iov[n].iov_len);
		assert(res >= 0);
		assert((size_t) res == iov[n].iov_len);
		total += res;
	}

	return fstrm_res_success;
}

static fstrm_res
reader_read(void *obj, void *data, size_t count)
{
	fstrm_fd_t *ffd = (fstrm_fd_t *) obj;
	uint8_t *dptr = (uint8_t *) data;
	size_t nleft = count;

	while (nleft > 0) {
		ssize_t got;

		got = read(ffd->fd, dptr, nleft);

		if (got == 0)
			return fstrm_res_stop;

		assert(got > 0);
		nleft -= got;
		dptr += got;
	}

	return fstrm_res_success;
}

static void
signal_handler(int signo)
{
	if (signo == SIGUSR1) {
		debug("Got SIGUSR1");
		sigusr1 = true;
	}
}

static int
fork_into(handler_func fn)
{
	int res = fork();
	if (res < 0) {
		perror("Fork failed");
		exit(EXIT_FAILURE);
	}

	if (res == 0) {
		exit(fn());
	}

	return res;
}

static void
do_kill(int pid, int signo)
{
	debug("Sending signal to %d", pid);
	if (kill(pid, signo) < 0) {
		perror("Failed to send signal");
		if (reader != 0)
			kill(reader, SIGKILL);
		if (writer != 0)
			kill(writer, SIGKILL);
		exit(EXIT_FAILURE);
	}
}

static int
writer_handler(void)
{
	struct fstrm_iothr *iothr = NULL;
	struct fstrm_iothr_queue *ioq = NULL;
	struct fstrm_writer *wr = NULL;

	header = "WRITER";
	debug("writer_handler %d", getpid());
	wr = (sock_addr ? get_unix_writer(sock_addr, g_read_timeout) : get_tcp_writer(address, port, g_read_timeout));
	iothr = fstrm_iothr_init(NULL, &wr);
	if (iothr == NULL) {
		debug("Error: fstrm_iothr_init() failed.");
		return EXIT_FAILURE;
	}

	ioq = fstrm_iothr_get_input_queue(iothr);
	if (ioq == NULL) {
		debug("Error: fstrm_iothr_get_input_queue() failed.");
		return EXIT_FAILURE;
	}

	debug("Writing messages");
	for (size_t x = 0; x < 10000; x++) {
		char *FOO = strdup("ABC");
		(void) fstrm_iothr_submit(iothr, ioq, FOO, strlen(FOO), fstrm_free_wrapper, NULL);
	}

	debug("Done writing. Signaling master");
	do_kill(master, SIGUSR1);

	debug("Waiting for master's signal");
	while (!sigusr1) {
		poll(NULL, 0, 100);
	}

	debug("Done");
	fstrm_iothr_destroy(&iothr);
	return EXIT_SUCCESS;
}

static int
reader_handler(void)
{
	int res;
	fstrm_fd_t ffd;
	struct fstrm_reader *r;
	struct fstrm_rdwr *rdwr = fstrm_rdwr_init(&ffd);
	assert(rdwr != NULL);

	header = "READER";
	debug("reader_handler %d", getpid());
	fstrm_rdwr_set_destroy(rdwr, reader_destroy);
	fstrm_rdwr_set_open(rdwr, reader_open);
	fstrm_rdwr_set_close(rdwr, reader_close);
	fstrm_rdwr_set_write(rdwr, reader_write);
	fstrm_rdwr_set_read(rdwr, reader_read);

	r = fstrm_reader_init(NULL, &rdwr);
	assert(r != NULL);

	assert(fstrm_reader_open(r) == fstrm_res_success);

	debug("READING...");
	while (!sigusr1) {
		const uint8_t *data;
		size_t len_data;

		res = fstrm_reader_read(r, &data, &len_data);
		if (res != fstrm_res_success) {
			debug("OH NO: %u", res);
			break;
		}
	}

	debug("Done reading");

	res = fstrm_reader_close(r);
	if (res != fstrm_res_success)
		debug("Error: fstrm_reader_close() failed");

	fstrm_reader_destroy(&r);

	return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
	int wstatus = 0;

	master = getpid();
	debug("Starting %d", master);
	parse_args(argc, argv);
	signal(SIGUSR1, signal_handler);

	debug("Starting reader");
	reader = fork_into(reader_handler);
	sleep(1);
	debug("Starting writer");
	writer = fork_into(writer_handler);

	debug("Waiting for writer's signal");
	while (!sigusr1) {
		poll(NULL, 0, 100);
	}

	debug("Stopping reader");
	do_kill(reader, SIGSTOP);
	debug("Signaling writer");
	do_kill(writer, SIGUSR1);

	debug("Waiting for writer to finish");
	waitpid(writer, &wstatus, 0);

	debug("Resuming reader");
	do_kill(reader, SIGCONT);
	debug("Stopping reader");
	do_kill(reader, SIGUSR1);

	debug("Waiting for reader to finish");
	waitpid(reader, &wstatus, 0);

	debug("Done");
	return EXIT_SUCCESS;
}