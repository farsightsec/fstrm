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
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
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
			printf("%s: got a control frame\n", __func__);
			n = fread(&wire_len, sizeof(wire_len), 1, f);
			assert(!ferror(f) && !feof(f) && n == 1);
			len = ntohl(wire_len);
			printf("%s: control frame is %u bytes long\n", __func__, len);
			if (len > 0) {
				n = fread(message, len, 1, f);
				assert(!ferror(f) && !feof(f) && n == 1);
				printf("%s: read a %u byte control frame\n", __func__, len);
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

	if (fclose(f)) {
		perror("fclose");
		abort();
	}
}

static int
consume_input(struct consumer *c, const char *file_path)
{
	int fd;

	memset(&c->cstat, 0, sizeof(c->cstat));

	fd = open(file_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: open() failed: %s\n", __func__, strerror(errno));
		return EXIT_FAILURE;
	}

	read_input(fd, &c->cstat);
	return EXIT_SUCCESS;
}

int
main(int argc, char **argv)
{
	struct timespec ts_a, ts_b;
	double elapsed;
	char *file_path;
	char *queue_model_str;
	unsigned num_messages;
	unsigned num_threads;
	fstrm_iothr_queue_model queue_model;

	if (argc != 5) {
		fprintf(stderr, "Usage: %s <FILE> <QUEUE MODEL> <NUM THREADS> <NUM MESSAGES>\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "FILE is a filesystem path.\n");
		fprintf(stderr, "QUEUE MODEL is the string 'SPSC' or 'MPSC'.\n");
		fprintf(stderr, "NUM THREADS is an integer.\n");
		fprintf(stderr, "NUM MESSAGES is an integer.\n");
		return EXIT_FAILURE;
	}
	file_path = argv[1];
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

	printf("testing fstrm_iothr with file= %s "
	       "queue_model= %s "
	       "num_threads= %u "
	       "num_messages= %u\n",
	       file_path, queue_model_str, num_threads, num_messages);

	struct fstrm_file_options *fopt;
	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, file_path);
	struct fstrm_writer *w = fstrm_file_writer_init(fopt, NULL);
	assert(w != NULL);
	fstrm_file_options_destroy(&fopt);

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

	struct fstrm_iothr *iothr = fstrm_iothr_init(iothr_opt, &w);
	assert(iothr != NULL);
	fstrm_iothr_options_destroy(&iothr_opt);

	struct consumer test_consumer;
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

	my_gettime(clock, &ts_b);
	my_timespec_sub(&ts_a, &ts_b);
	elapsed = my_timespec_to_double(&ts_b);
	printf("completed in %.2f seconds\n", elapsed);

	int res = consume_input(&test_consumer, file_path);
	if (res != EXIT_SUCCESS)
		return res;

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

	return EXIT_SUCCESS;
}
