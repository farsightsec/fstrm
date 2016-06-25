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

#include <assert.h>
#include <inttypes.h>
#include <locale.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libmy/my_alloc.h"
#include "libmy/my_time.h"

#include "libmy/my_memory_barrier.h"
#include "libmy/my_queue.h"

#ifdef MY_HAVE_MEMORY_BARRIERS
extern const struct my_queue_ops my_queue_mb_ops;
#endif

extern const struct my_queue_ops my_queue_mutex_ops;

const struct my_queue_ops *queue_ops;

struct producer_stats {
	uint64_t	count_producer_full;
	uint64_t	count_producer;
	uint64_t	checksum_producer;
	uint64_t	count_insert_calls;
};

struct consumer_stats {
	uint64_t	count_consumer_empty;
	uint64_t	count_consumer;
	uint64_t	count_remove_calls;
	uint64_t	checksum_consumer;
};

enum wait_type {
	wt_spin,
	wt_slow_producer,
	wt_slow_consumer,
};

static volatile bool shut_down;

static enum wait_type wtype;
static const char *wtype_s;

static unsigned seconds;

static struct my_queue *q;

static int size;

static inline void
maybe_wait_producer(int64_t i)
{
	if (wtype != wt_slow_producer)
		return;
	if ((i % 128) == 0) {
		struct timespec ts_wait = {
			.tv_sec = 0, .tv_nsec = 1
		};
		my_nanosleep(&ts_wait);
	}
}

static inline void
maybe_wait_consumer(int64_t i)
{
	if (wtype != wt_slow_consumer)
		return;
	if ((i % 128) == 0) {
		struct timespec ts_wait = {
			.tv_sec = 0, .tv_nsec = 1
		};
		my_nanosleep(&ts_wait);
	}
}

static void *
thr_producer(void *arg)
{
	bool res;
	unsigned space = 0;

	struct producer_stats *s;
	s = my_calloc(1, sizeof(*s));

	for (unsigned loops = 1; ; loops++) {
		for (int64_t i = 1; i <= 1000000; i++) {
			if (shut_down)
				goto out;

			res = queue_ops->insert(q, &i, &space);
			s->count_insert_calls++;
			if (res) {
				s->count_producer++;
				s->checksum_producer += i;
			} else {
				s->count_producer_full++;
			}
			maybe_wait_producer(i);
		}
	}
out:
	fprintf(stderr, "%s: producer thread shutting down\n", __func__);
	fprintf(stderr, "%s: count_producer= %" PRIu64 "\n", __func__, s->count_producer);
	fprintf(stderr, "%s: count_producer_full= %" PRIu64 "\n", __func__, s->count_producer_full);
	fprintf(stderr, "%s: count_insert_calls= %" PRIu64 "\n", __func__, s->count_insert_calls);
	fprintf(stderr, "%s: checksum_producer= %" PRIu64 "\n", __func__, s->checksum_producer);
	return (s);
}

static void *
thr_consumer(void *arg)
{
	bool res;
	unsigned count = 0;

	struct consumer_stats *s;
	s = my_calloc(1, sizeof(*s));

	for (unsigned loops = 1; ; loops++) {
		for (int64_t i = 1; i <= 1000000; i++) {
			res = queue_ops->remove(q, &i, &count);
			s->count_remove_calls++;
			if (res) {
				if (i == 0) {
					fprintf(stderr, "%s: received shutdown message\n", __func__);
					goto out;
				}
				s->checksum_consumer += i;
				s->count_consumer++;
			} else {
				s->count_consumer_empty++;
			}
			maybe_wait_consumer(i);
		}
	}
out:
	fprintf(stderr, "%s: count_consumer= %" PRIu64 "\n", __func__, s->count_consumer);
	fprintf(stderr, "%s: count_consumer_empty= %" PRIu64 "\n", __func__, s->count_consumer_empty);
	fprintf(stderr, "%s: count_remove_calls= %" PRIu64 "\n", __func__, s->count_remove_calls);
	fprintf(stderr, "%s: checksum_consumer= %" PRIu64 "\n", __func__, s->checksum_consumer);
	return (s);
}

static void
send_shutdown_message(struct my_queue *my_q)
{
	int64_t i = 0;
	while (!queue_ops->insert(my_q, &i, NULL));
}

static int
check_stats(struct producer_stats *ps, struct consumer_stats *cs)
{
	if (ps->checksum_producer != cs->checksum_consumer) {
		fprintf(stderr,
			"FATAL ERROR: producer checksum != consumer checksum "
			"(%" PRIu64 " != %" PRIu64 ")\n",
			ps->checksum_producer,
			cs->checksum_consumer
		);
		return EXIT_FAILURE;
	}
	if (ps->count_producer != cs->count_consumer) {
		fprintf(stderr, "FATAL ERROR: producer count != consumer count "
			"(%" PRIu64 " != %" PRIu64 ")\n",
			ps->count_producer,
			cs->count_consumer
		);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static void
print_stats(struct timespec *a, struct timespec *b,
	    struct producer_stats *ps, struct consumer_stats *cs)
{
	double dur;
	dur = my_timespec_to_double(b) - my_timespec_to_double(a);

	fprintf(stderr, "%s: ran for %'.4f seconds in %s mode\n", __func__, dur, wtype_s);
	fprintf(stderr, "%s: producer: %'.0f iter/sec [%d nsec/iter] (%.2f%% full)\n",
		__func__,
		ps->count_insert_calls / dur,
		(int) (1E9 * dur / ps->count_insert_calls),
		100.0 * ps->count_producer_full / ps->count_insert_calls
	);
	fprintf(stderr, "%s: consumer: %'.0f iter/sec [%d nsec/iter] (%.2f%% empty)\n",
		__func__,
		cs->count_remove_calls / dur,
		(int) (1E9 * dur / cs->count_remove_calls),
		100.0 * cs->count_consumer_empty / cs->count_remove_calls
	);
}

static int
run_test(void)
{
	int res;
	struct timespec ts_a, ts_b;
	struct producer_stats *ps;
	struct consumer_stats *cs;
	struct timespec ts = { .tv_sec = seconds, .tv_nsec = 0 };

	q = queue_ops->init(size, sizeof(int64_t));
	if (q == NULL) {
		fprintf(stderr, "queue_ops->init() failed, size too small or not a power-of-2?\n");
		return (EXIT_FAILURE);
	}
	fprintf(stderr, "queue implementation type: %s\n", queue_ops->impl_type());
	fprintf(stderr, "queue size: %d entries\n", size);
	fprintf(stderr, "running for %d seconds\n", seconds);

	pthread_t thr_p;
	pthread_t thr_c;

#if HAVE_CLOCK_GETTIME
	const clockid_t clock = CLOCK_MONOTONIC;
#else
	const int clock = -1;
#endif
	my_gettime(clock, &ts_a);

	pthread_create(&thr_p, NULL, thr_producer, NULL);
	pthread_create(&thr_c, NULL, thr_consumer, NULL);

	my_nanosleep(&ts);
	shut_down = true;

	pthread_join(thr_p, (void **) &ps);
	send_shutdown_message(q);
	pthread_join(thr_c, (void **) &cs);

	my_gettime(clock, &ts_b);

	res = check_stats(ps, cs);
	print_stats(&ts_a, &ts_b, ps, cs);

	free(ps);
	free(cs);

	queue_ops->destroy(&q);

	return res;
}

int
main(int argc, char **argv)
{
	int res;

	setlocale(LC_ALL, "");

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <slow_producer | slow_consumer | spin> <QUEUE SIZE> <RUN SECONDS>\n", argv[0]);
		return (EXIT_FAILURE);
	}
	if (strcasecmp(argv[1], "slow_producer") == 0) {
		wtype = wt_slow_producer;
		wtype_s = "slow producer";
	} else if (strcasecmp(argv[1], "slow_consumer") == 0) {
		wtype = wt_slow_consumer;
		wtype_s = "slow consumer";
	} else if (strcasecmp(argv[1], "spin") == 0) {
		wtype = wt_spin;
		wtype_s = "spin";
	} else {
		fprintf(stderr, "Error: invalid wait type '%s'\n", argv[1]);
		return (EXIT_FAILURE);
	}
	size = atoi(argv[2]);
	seconds = atoi(argv[3]);

#ifdef MY_HAVE_MEMORY_BARRIERS
	queue_ops = &my_queue_mb_ops;
	res = run_test();
	if (res != EXIT_SUCCESS)
		return res;
#endif

	shut_down = false;

	queue_ops = &my_queue_mutex_ops;
	res = run_test();
	if (res != EXIT_SUCCESS)
		return res;

	return EXIT_SUCCESS;
}
