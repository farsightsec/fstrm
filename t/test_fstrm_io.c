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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fstrm.h"

#include "libmy/my_alloc.h"
#include "libmy/my_time.h"
#include "libmy/rate.h"
#include "libmy/ubuf.h"

#define MAX_MESSAGE_SIZE	4096
#define MESSAGE_RATE		100000

struct producer_stats {
	uint64_t	count_generated;
	uint64_t	count_submitted;
	uint64_t	bytes_generated;
	uint64_t	bytes_submitted;
};

struct consumer_stats {
	uint64_t	count_received;
	uint64_t	bytes_received;
};

static unsigned num_messages;

static struct fstrm_io *fio;

static const char *test_string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static int server_fd;

static void *
thr_producer(void *arg)
{
	struct producer_stats *pstat = (struct producer_stats *) arg;
	struct fstrm_queue *fq;
	struct rate *r;

	fq = fstrm_io_get_queue(fio);
	assert(fq != NULL);

	r = rate_init(MESSAGE_RATE, 100);
	assert(r != NULL);

	memset(pstat, 0, sizeof(*pstat));

	for (unsigned i = 0; i < num_messages; i++) {
		int res;
		size_t len = 0;
		uint8_t *message = NULL;
		ubuf *u = ubuf_init(512);

		unsigned ndups = (pstat->count_generated % 4) + 1;
		for (unsigned j = 0; j < ndups; j++)
			ubuf_add_cstr(u, test_string);

		ubuf_detach(u, &message, &len);
		ubuf_destroy(&u);

		res = fstrm_io_submit(fio, fq, message, (uint32_t) len, NULL, NULL);
		if (res > 0) {
			pstat->count_submitted++;
			pstat->bytes_submitted += len;
		}
		pstat->count_generated++;
		pstat->bytes_generated += len;

		rate_sleep(r);
	}

	rate_destroy(&r);
	return (NULL);
}

static void
read_input(int fd, struct consumer_stats *cstat)
{
	FILE *f;

	f = fdopen(fd, "r");
	if (f == NULL) {
		perror("fdopen");
		abort();
	}

	for (;;) {
		size_t nbytes;
		uint32_t len;
		uint8_t message[MAX_MESSAGE_SIZE];

		nbytes = fread(&len, sizeof(len), 1, f);
		if (ferror(f))
			break;
		if (nbytes == 0 && feof(f)) {
			printf("%s(): got EOF\n", __func__);
			break;
		}

		len = ntohl(len);
		if (len == 0)
			continue;

		assert(len < MAX_MESSAGE_SIZE);
		nbytes = fread(message, len, 1, f);
		if (ferror(f))
			break;
		if (nbytes == 0 && feof(f)) {
			printf("%s(): EOF while reading message\n", __func__);
			abort();
		}

		cstat->count_received++;
		cstat->bytes_received += len;
	}

	if (fclose(f)) {
		perror("fclose");
		abort();
	}
}

static void *
thr_consumer(void *arg)
{
	struct consumer_stats *cstat = (struct consumer_stats *) arg;
	int client_fd;

	memset(cstat, 0, sizeof(*cstat));

	client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		perror("accept");
		abort();
	}
	printf("%s(): accepted a connection\n", __func__);

	read_input(client_fd, cstat);

	if (close(server_fd) == -1) {
		perror("close");
		abort();
	}

	printf("%s(): exiting\n", __func__);
	return (NULL);
}

static int
get_server_socket(const char *socket_path)
{
	struct sockaddr_un sa;
	int sfd;

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1) {
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

	if (bind(sfd, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
		perror("bind");
		abort();
	}

	if (listen(sfd, 1) == -1) {
		perror("listen");
		abort();
	}

	return (sfd);
}

int
main(int argc, char **argv)
{
	struct timespec ts_a, ts_b;
	double elapsed;
	char *socket_path;
	unsigned num_threads;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <SOCKET> <NUM THREADS> <NUM MESSAGES>\n", argv[0]);
		return (EXIT_FAILURE);
	}
	socket_path = argv[1];
	num_threads = atoi(argv[2]);
	num_messages = atoi(argv[3]);
	if (num_threads < 1) {
		fprintf(stderr, "%s: Error: invalid number of threads\n", argv[0]);
		return (EXIT_FAILURE);
	}
	if (num_messages < 1) {
		fprintf(stderr, "%s: Error: invalid number of messages\n", argv[0]);
		return (EXIT_FAILURE);
	}

	printf("testing fstrm_io with socket= %s num_threads= %u num_messages= %u\n",
	       socket_path, num_threads, num_messages);

	printf("opening server socket on %s\n", socket_path);
	server_fd = get_server_socket(socket_path);

	struct producer_stats pstat[num_threads];
	struct consumer_stats cstat;

	pthread_t thr_p[num_threads];
	pthread_t thr_c;

	printf("creating consumer thread\n");
	pthread_create(&thr_c, NULL, thr_consumer, &cstat);

	struct fstrm_unix_writer_options *fuwopt;
	fuwopt = fstrm_unix_writer_options_init();
	fstrm_unix_writer_options_set_socket_path(fuwopt, socket_path);

	struct fstrm_io_options *fopt;
	fopt = fstrm_io_options_init();
	fstrm_io_options_set_num_queues(fopt, num_threads);
	fstrm_io_options_set_writer(fopt, fstrm_unix_writer, fuwopt);

	char *errstr = NULL;
	fio = fstrm_io_init(fopt, &errstr);
	if (fio == NULL) {
		fprintf(stderr, "%s: Error: fstrm_io_init() failed: %s\n", argv[0], errstr);
		free(errstr);
		return (EXIT_FAILURE);
	}
	fstrm_io_options_destroy(&fopt);
	fstrm_unix_writer_options_destroy(&fuwopt);

	my_gettime(CLOCK_MONOTONIC, &ts_a);

	printf("creating %u producer threads\n", num_threads);
	for (unsigned i = 0; i < num_threads; i++)
		pthread_create(&thr_p[i], NULL, thr_producer, &pstat[i]);

	printf("joining %u producer threads\n", num_threads);
	for (unsigned i = 0; i < num_threads; i++)
		pthread_join(thr_p[i], (void **) NULL);

	printf("destroying fstrm_io object\n");
	fstrm_io_destroy(&fio);

	printf("joining consumer thread\n");
	pthread_join(thr_c, (void **) NULL);

	my_gettime(CLOCK_MONOTONIC, &ts_b);
	my_timespec_sub(&ts_a, &ts_b);
	elapsed = my_timespec_to_double(&ts_b);
	printf("completed in %.2f seconds\n", elapsed);

	struct producer_stats pstat_sum;
	memset(&pstat_sum, 0, sizeof(pstat_sum));
	for (unsigned i = 0; i < num_threads; i++) {
		pstat_sum.count_generated += pstat[i].count_generated;
		pstat_sum.count_submitted += pstat[i].count_submitted;
		pstat_sum.bytes_generated += pstat[i].bytes_generated;
		pstat_sum.bytes_submitted += pstat[i].bytes_submitted;
	}
	printf("count_generated= %" PRIu64 "\n", pstat_sum.count_generated);
	printf("bytes_generated= %" PRIu64 "\n", pstat_sum.bytes_generated);
	printf("count_submitted= %" PRIu64 "\n", pstat_sum.count_submitted);
	printf("bytes_submitted= %" PRIu64 "\n", pstat_sum.bytes_submitted);

	printf("count_received= %" PRIu64 " (%.3f)\n",
	       cstat.count_received,
	       (cstat.count_received + 0.0) / (pstat_sum.count_generated + 0.0)
	);
	printf("bytes_received= %" PRIu64 " (%.3f)\n",
	       cstat.bytes_received,
	       (cstat.bytes_received + 0.0) / (pstat_sum.bytes_generated + 0.0)
	);

	assert(pstat_sum.count_submitted == cstat.count_received);
	assert(pstat_sum.bytes_submitted == cstat.bytes_received);

	putchar('\n');

	return (EXIT_SUCCESS);
}
