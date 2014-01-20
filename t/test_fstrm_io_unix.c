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
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fstrm.h"

#include "libmy/my_alloc.h"
#include "libmy/my_time.h"
#include "libmy/ubuf.h"

#define MAX_MESSAGE_SIZE	4096

struct producer_stats {
	uint64_t		count_generated;
	uint64_t		count_submitted;
	uint64_t		bytes_generated;
	uint64_t		bytes_submitted;
};

struct producer {
	pthread_t		thr;
	struct producer_stats	pstat;
	struct fstrm_queue	*fq;
};

struct consumer_stats {
	uint64_t		count_received;
	uint64_t		bytes_received;
};

struct consumer {
	pthread_t		thr;
	struct consumer_stats	cstat;
};

static unsigned num_messages;

static struct fstrm_io *fio;

static const char *test_string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static int server_fd;

static void *
thr_producer(void *arg)
{
	struct producer *p = (struct producer *) arg;

	memset(&p->pstat, 0, sizeof(p->pstat));

	for (unsigned i = 0; i < num_messages; i++) {
		fstrm_res res;
		size_t len = 0;
		uint8_t *message = NULL;
		ubuf *u = ubuf_init(512);

		unsigned ndups = (p->pstat.count_generated % 4) + 1;
		for (unsigned j = 0; j < ndups; j++)
			ubuf_add_cstr(u, test_string);

		ubuf_detach(u, &message, &len);
		ubuf_destroy(&u);

		res = fstrm_io_submit(fio, p->fq, message, len, fstrm_free_wrapper, NULL);
		if (res == FSTRM_RES_SUCCESS) {
			p->pstat.count_submitted++;
			p->pstat.bytes_submitted += len;
		} else {
			free(message);
		}
		p->pstat.count_generated++;
		p->pstat.bytes_generated += len;

		if ((i % 1000) == 0)
			poll(NULL, 0, 1);
	}

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
		uint32_t len, wire_len;
		uint8_t message[MAX_MESSAGE_SIZE];

		nbytes = fread(&wire_len, sizeof(wire_len), 1, f);
		if (ferror(f)) {
			printf("%s: fread() errored\n", __func__);
			break;
		} if (nbytes == 0 && feof(f)) {
			printf("%s: got EOF\n", __func__);
			break;
		}

		len = ntohl(wire_len);
		if (len == 0) {
			/* Skip the control frame. */
			printf("%s: got a control frame\n", __func__);
			nbytes = fread(&wire_len, sizeof(wire_len), 1, f);
			assert(!ferror(f) && !feof(f));
			len = ntohl(wire_len);
			printf("%s: control frame is %u bytes long\n", __func__, len);
			if (len > 0) {
				nbytes = fread(message, len, 1, f);
				assert(!ferror(f) && !feof(f));
				printf("%s: read a %u byte control frame\n", __func__, len);
			}
			continue;
		}

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
	struct consumer *c = (struct consumer *) arg;
	int client_fd;

	memset(&c->cstat, 0, sizeof(c->cstat));

	client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		perror("accept");
		abort();
	}
	printf("%s(): accepted a connection\n", __func__);

	read_input(client_fd, &c->cstat);

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
	char *queue_model_str;
	unsigned num_threads;
	fstrm_queue_model queue_model;

	if (argc != 5) {
		fprintf(stderr, "Usage: %s <SOCKET> <QUEUE MODEL> <NUM THREADS> <NUM MESSAGES>\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "SOCKET is a filesystem path.\n");
		fprintf(stderr, "QUEUE MODEL is the string 'SPSC' or 'MPSC'.\n");
		fprintf(stderr, "NUM THREADS is an integer.\n");
		fprintf(stderr, "NUM MESSAGES is an integer.\n");
		return (EXIT_FAILURE);
	}
	socket_path = argv[1];
	queue_model_str = argv[2];
	num_threads = atoi(argv[3]);
	num_messages = atoi(argv[4]);
	if (num_threads < 1) {
		fprintf(stderr, "%s: Error: invalid number of threads\n", argv[0]);
		return (EXIT_FAILURE);
	}
	if (num_messages < 1) {
		fprintf(stderr, "%s: Error: invalid number of messages\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (strcasecmp(queue_model_str, "SPSC") == 0) {
		queue_model = FSTRM_QUEUE_MODEL_SPSC;
	} else if (strcasecmp(queue_model_str, "MPSC") == 0) {
		queue_model = FSTRM_QUEUE_MODEL_MPSC;
	} else {
		fprintf(stderr, "%s: Error: invalid queue model\n", argv[0]);
		return (EXIT_FAILURE);
	}

	printf("testing fstrm_io with socket= %s "
	       "queue_model= %s "
	       "num_threads= %u "
	       "num_messages= %u\n",
	       socket_path, queue_model_str, num_threads, num_messages);

	printf("opening server socket on %s\n", socket_path);
	server_fd = get_server_socket(socket_path);

	struct producer test_producers[num_threads];
	struct consumer test_consumer;

	printf("creating consumer thread\n");
	pthread_create(&test_consumer.thr, NULL, thr_consumer, &test_consumer);

	struct fstrm_unix_writer_options *fuwopt;
	fuwopt = fstrm_unix_writer_options_init();
	fstrm_unix_writer_options_set_socket_path(fuwopt, socket_path);

	struct fstrm_io_options *fopt;
	fopt = fstrm_io_options_init();

	if (queue_model == FSTRM_QUEUE_MODEL_SPSC) {
		fstrm_io_options_set_num_queues(fopt, num_threads);
	} else if (queue_model == FSTRM_QUEUE_MODEL_MPSC) {
		fstrm_io_options_set_num_queues(fopt, 1);
	} else {
		assert(0); /* not reached */
	}
	fstrm_io_options_set_queue_model(fopt, queue_model);
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

	if (queue_model == FSTRM_QUEUE_MODEL_SPSC) {
		for (unsigned i = 0; i < num_threads; i++) {
			test_producers[i].fq = fstrm_io_get_queue(fio);
			assert(test_producers[i].fq != NULL);
		}
	} else if (queue_model == FSTRM_QUEUE_MODEL_MPSC) {
		struct fstrm_queue *fq = fstrm_io_get_queue(fio);
		assert(fq != NULL);
		for (unsigned i = 0; i < num_threads; i++)
			test_producers[i].fq = fq;
	} else {
		assert(0); /* not reached */
	}

	my_gettime(CLOCK_MONOTONIC, &ts_a);

	printf("creating %u producer threads\n", num_threads);
	for (unsigned i = 0; i < num_threads; i++)
		pthread_create(&test_producers[i].thr, NULL, thr_producer, &test_producers[i]);

	printf("joining %u producer threads\n", num_threads);
	for (unsigned i = 0; i < num_threads; i++)
		pthread_join(test_producers[i].thr, (void **) NULL);

	printf("destroying fstrm_io object\n");
	fstrm_io_destroy(&fio);

	printf("joining consumer thread\n");
	pthread_join(test_consumer.thr, (void **) NULL);

	my_gettime(CLOCK_MONOTONIC, &ts_b);
	my_timespec_sub(&ts_a, &ts_b);
	elapsed = my_timespec_to_double(&ts_b);
	printf("completed in %.2f seconds\n", elapsed);

	struct producer_stats pstat_sum;
	memset(&pstat_sum, 0, sizeof(pstat_sum));
	for (unsigned i = 0; i < num_threads; i++) {
		pstat_sum.count_generated += test_producers[i].pstat.count_generated;
		pstat_sum.count_submitted += test_producers[i].pstat.count_submitted;
		pstat_sum.bytes_generated += test_producers[i].pstat.bytes_generated;
		pstat_sum.bytes_submitted += test_producers[i].pstat.bytes_submitted;
	}
	printf("count_generated= %" PRIu64 "\n", pstat_sum.count_generated);
	printf("bytes_generated= %" PRIu64 "\n", pstat_sum.bytes_generated);
	printf("count_submitted= %" PRIu64 "\n", pstat_sum.count_submitted);
	printf("bytes_submitted= %" PRIu64 "\n", pstat_sum.bytes_submitted);

	printf("count_received= %" PRIu64 " (%.3f)\n",
	       test_consumer.cstat.count_received,
	       (test_consumer.cstat.count_received + 0.0) / (pstat_sum.count_generated + 0.0)
	);
	printf("bytes_received= %" PRIu64 " (%.3f)\n",
	       test_consumer.cstat.bytes_received,
	       (test_consumer.cstat.bytes_received + 0.0) / (pstat_sum.bytes_generated + 0.0)
	);

	assert(pstat_sum.count_submitted == test_consumer.cstat.count_received);
	assert(pstat_sum.bytes_submitted == test_consumer.cstat.bytes_received);

	putchar('\n');

	return (EXIT_SUCCESS);
}
