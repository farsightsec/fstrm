/*
 * Copyright (c) 2013-2016 by Farsight Security, Inc.
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

#include <fstrm.h>

#include "libmy/my_alloc.h"
#include "libmy/my_time.h"
#include "libmy/print_string.h"
#include "libmy/ubuf.h"

#define MAX_MESSAGE_SIZE	4096

static const char *test_string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

struct producer_stats {
	uint64_t			count_generated;
	uint64_t			count_submitted;
	uint64_t			bytes_generated;
	uint64_t			bytes_submitted;
};

struct producer {
	pthread_t			thr;
	struct producer_stats		pstat;
	struct fstrm_iothr		*iothr;
	struct fstrm_iothr_queue	*ioq;
	unsigned			num_messages;
};

struct consumer_stats {
	uint64_t			count_received;
	uint64_t			bytes_received;
};

struct consumer {
	pthread_t			thr;
	int				server_fd;
	struct consumer_stats		cstat;
};

static void *
thr_producer(void *arg)
{
	struct producer *p = (struct producer *) arg;

	memset(&p->pstat, 0, sizeof(p->pstat));

	for (unsigned i = 0; i < p->num_messages; i++) {
		fstrm_res res;
		size_t len = 0;
		uint8_t *message = NULL;
		ubuf *u = ubuf_init(512);

		unsigned ndups = (p->pstat.count_generated % 4) + 1;
		for (unsigned j = 0; j < ndups; j++)
			ubuf_add_cstr(u, test_string);

		ubuf_detach(u, &message, &len);
		ubuf_destroy(&u);

		res = fstrm_iothr_submit(p->iothr, p->ioq,
			message, len, fstrm_free_wrapper, NULL);
		if (res == fstrm_res_success) {
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

	return NULL;
}

static fstrm_control_type
decode_control_frame(struct fstrm_control *c, const uint8_t *frame, const size_t len)
{
	fstrm_res res;

	/* Decode the control frame. */
	res = fstrm_control_decode(c, frame, len, 0);
	assert(res == fstrm_res_success);

	/* Return the control frame type. */
	fstrm_control_type type;
	res = fstrm_control_get_type(c, &type);
	assert(res == fstrm_res_success);
	printf("%s: got a %s\n", __func__, fstrm_control_type_to_str(type));
	return type;
}

static fstrm_control_type
read_control_frame(FILE *f, struct fstrm_control *c)
{
	uint8_t frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	uint32_t len_control_frame;
	uint32_t tmp;
	size_t n;

	/* Read the escape sequence. */
	n = fread(&tmp, sizeof(tmp), 1, f);
	assert(!ferror(f) && !feof(f) && n == 1);
	assert(ntohl(tmp) == 0);

	/* Read the control frame length. */
	n = fread(&tmp, sizeof(tmp), 1, f);
	assert(!ferror(f) && !feof(f) && n == 1);
	len_control_frame = ntohl(tmp);
	assert(len_control_frame <= FSTRM_CONTROL_FRAME_LENGTH_MAX);

	/* Read the control frame. */
	n = fread(frame, len_control_frame, 1, f);
	assert(!ferror(f) && !feof(f) && n == 1);

	return decode_control_frame(c, frame, len_control_frame);
}

static void
write_control_frame(int fd, struct fstrm_control *c, fstrm_control_type type)
{
	fstrm_res res;
	const uint32_t flags = FSTRM_CONTROL_FLAG_WITH_HEADER;
	size_t len_control_frame;

	res = fstrm_control_set_type(c, type);
	assert(res == fstrm_res_success);

	res = fstrm_control_encoded_size(c, &len_control_frame, flags);
	assert(res == fstrm_res_success);

	uint8_t control_frame[len_control_frame];
	res = fstrm_control_encode(c, control_frame, &len_control_frame, flags);
	assert(res == fstrm_res_success);

	size_t n_written = (size_t) write(fd, control_frame, len_control_frame);
	assert(n_written == len_control_frame);

	printf("%s: wrote a %s\n", __func__, fstrm_control_type_to_str(type));
}

static void
print_content_types(struct fstrm_control *c)
{
	fstrm_res res;
	size_t n_ctype = 0;
	fstrm_control_type type;

	res = fstrm_control_get_type(c, &type);
	assert(res == fstrm_res_success);


	res = fstrm_control_get_num_field_content_type(c, &n_ctype);
	assert(res == fstrm_res_success);

	for (size_t idx = 0; idx < n_ctype; idx++) {
		const uint8_t *ctype;
		size_t len_ctype;

		res = fstrm_control_get_field_content_type(c, idx, &ctype, &len_ctype);
		assert(res == fstrm_res_success);

		printf("%s: %s has CONTENT_TYPE field: ", __func__,
		       fstrm_control_type_to_str(type));
		print_string(ctype, len_ctype, stdout);
		putchar('\n');
	}
}

static void
read_input(int fd, struct consumer_stats *cstat)
{
	FILE *f;
	fstrm_control_type type;

	f = fdopen(fd, "r");
	if (f == NULL) {
		perror("fdopen failed");
		abort();
	}

	struct fstrm_control *c;
	c = fstrm_control_init();

	type = read_control_frame(f, c);
	assert(type == FSTRM_CONTROL_READY);
	print_content_types(c);

	write_control_frame(fd, c, FSTRM_CONTROL_ACCEPT);

	type = read_control_frame(f, c);
	assert(type == FSTRM_CONTROL_START);
	print_content_types(c);

	for (;;) {
		size_t n;
		uint32_t len, wire_len;
		uint8_t message[MAX_MESSAGE_SIZE];

		n = fread(&wire_len, sizeof(wire_len), 1, f);
		if (ferror(f)) {
			printf("%s: fread() errored\n", __func__);
			break;
		} if (n == 0 && feof(f)) {
			printf("%s: got EOF\n", __func__);
			break;
		}

		len = ntohl(wire_len);
		if (len == 0) {
			/* Skip the control frame. */
			n = fread(&wire_len, sizeof(wire_len), 1, f);
			assert(!ferror(f) && !feof(f) && n == 1);
			len = ntohl(wire_len);
			if (len > 0) {
				n = fread(message, len, 1, f);
				assert(!ferror(f) && !feof(f) && n == 1);
				type = decode_control_frame(c, message, len);
				printf("%s: read a %u byte control frame (%s)\n",
				       __func__, len, fstrm_control_type_to_str(type));
				if (type == FSTRM_CONTROL_STOP) {
					printf("%s: shutting down\n", __func__);
					break;
				}
			}
			continue;
		}

		assert(len < MAX_MESSAGE_SIZE);
		n = fread(message, len, 1, f);
		if (ferror(f))
			break;
		if (n == 0 && feof(f)) {
			printf("%s(): EOF while reading message\n", __func__);
			abort();
		}

		cstat->count_received++;
		cstat->bytes_received += len;
	}

	write_control_frame(fd, c, FSTRM_CONTROL_FINISH);

	if (fclose(f)) {
		perror("fclose");
		abort();
	}

	fstrm_control_destroy(&c);
}

static void *
thr_consumer(void *arg)
{
	struct consumer *c = (struct consumer *) arg;
	int client_fd;

	memset(&c->cstat, 0, sizeof(c->cstat));

	client_fd = accept(c->server_fd, NULL, NULL);
	if (client_fd == -1) {
		perror("accept");
		abort();
	}
	printf("%s(): accepted a connection\n", __func__);

	read_input(client_fd, &c->cstat);

	if (close(c->server_fd) == -1) {
		perror("close");
		abort();
	}

	printf("%s(): exiting\n", __func__);
	return NULL;
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

	return sfd;
}

int
main(int argc, char **argv)
{
	struct timespec ts_a, ts_b;
	double elapsed;
	char *socket_path;
	char *queue_model_str;
	unsigned num_messages;
	unsigned num_threads;
	fstrm_iothr_queue_model queue_model;

	if (argc != 5) {
		fprintf(stderr, "Usage: %s <SOCKET> <QUEUE MODEL> <NUM THREADS> <NUM MESSAGES>\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "SOCKET is a filesystem path.\n");
		fprintf(stderr, "QUEUE MODEL is the string 'SPSC' or 'MPSC'.\n");
		fprintf(stderr, "NUM THREADS is an integer.\n");
		fprintf(stderr, "NUM MESSAGES is an integer.\n");
		return EXIT_FAILURE;
	}
	socket_path = argv[1];
	queue_model_str = argv[2];
	num_threads = atoi(argv[3]);
	num_messages = atoi(argv[4]);
	if (num_threads < 1) {
		fprintf(stderr, "%s: Error: invalid number of threads\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (num_messages < 1) {
		fprintf(stderr, "%s: Error: invalid number of messages\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (strcasecmp(queue_model_str, "SPSC") == 0) {
		queue_model = FSTRM_IOTHR_QUEUE_MODEL_SPSC;
	} else if (strcasecmp(queue_model_str, "MPSC") == 0) {
		queue_model = FSTRM_IOTHR_QUEUE_MODEL_MPSC;
	} else {
		fprintf(stderr, "%s: Error: invalid queue model\n", argv[0]);
		return EXIT_FAILURE;
	}

	printf("setting up 300 second timeout\n");
	alarm(300);

	printf("testing fstrm_iothr with socket= %s "
	       "queue_model= %s "
	       "num_threads= %u "
	       "num_messages= %u\n",
	       socket_path, queue_model_str, num_threads, num_messages);

	struct fstrm_unix_writer_options *uwopt;
	uwopt = fstrm_unix_writer_options_init();
	fstrm_unix_writer_options_set_socket_path(uwopt, socket_path);
	struct fstrm_writer *w = fstrm_unix_writer_init(uwopt, NULL);
	assert(w != NULL);
	fstrm_unix_writer_options_destroy(&uwopt);

	struct fstrm_iothr_options *iothr_opt;
	iothr_opt = fstrm_iothr_options_init();

	if (queue_model == FSTRM_IOTHR_QUEUE_MODEL_SPSC) {
		fstrm_iothr_options_set_num_input_queues(iothr_opt, num_threads);
	} else if (queue_model == FSTRM_IOTHR_QUEUE_MODEL_MPSC) {
		fstrm_iothr_options_set_num_input_queues(iothr_opt, 1);
	} else {
		assert(0); /* not reached */
	}
	fstrm_iothr_options_set_queue_model(iothr_opt, queue_model);

	struct consumer test_consumer;
	printf("opening server socket on %s\n", socket_path);
	test_consumer.server_fd = get_server_socket(socket_path);

	printf("creating consumer thread\n");
	pthread_create(&test_consumer.thr, NULL, thr_consumer, &test_consumer);

	struct fstrm_iothr *iothr = fstrm_iothr_init(iothr_opt, &w);
	assert(iothr != NULL);
	fstrm_iothr_options_destroy(&iothr_opt);

	struct producer test_producers[num_threads];

	for (unsigned i = 0; i < num_threads; i++) {
		test_producers[i].iothr = iothr;
		test_producers[i].num_messages = num_messages;
	}

	if (queue_model == FSTRM_IOTHR_QUEUE_MODEL_SPSC) {
		for (unsigned i = 0; i < num_threads; i++) {
			test_producers[i].ioq = fstrm_iothr_get_input_queue(iothr);
			assert(test_producers[i].ioq != NULL);
		}
	} else if (queue_model == FSTRM_IOTHR_QUEUE_MODEL_MPSC) {
		struct fstrm_iothr_queue *ioq = fstrm_iothr_get_input_queue(iothr);
		assert(ioq != NULL);
		for (unsigned i = 0; i < num_threads; i++)
			test_producers[i].ioq = ioq;
	} else {
		assert(0); /* not reached */
	}

#if HAVE_CLOCK_GETTIME
	const clockid_t clock = CLOCK_MONOTONIC;
#else
	const int clock = -1;
#endif
	my_gettime(clock, &ts_a);

	printf("creating %u producer threads\n", num_threads);
	for (unsigned i = 0; i < num_threads; i++)
		pthread_create(&test_producers[i].thr, NULL, thr_producer, &test_producers[i]);

	printf("joining %u producer threads\n", num_threads);
	for (unsigned i = 0; i < num_threads; i++)
		pthread_join(test_producers[i].thr, (void **) NULL);

	printf("destroying fstrm_iothr object\n");
	fstrm_iothr_destroy(&iothr);

	printf("joining consumer thread\n");
	pthread_join(test_consumer.thr, (void **) NULL);

	my_gettime(clock, &ts_b);
	my_timespec_sub(&ts_a, &ts_b);
	elapsed = my_timespec_to_double(&ts_b);
	printf("completed in %.2f seconds\n", elapsed);

	struct producer_stats pstat_sum = {0};
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

	return EXIT_SUCCESS;
}
