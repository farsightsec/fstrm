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

#include "fstrm-private.h"

bool
fs_get_best_monotonic_clock_pthread(clockid_t *c)
{
	bool res = false;
	int rc;
	struct timespec ts;
	pthread_condattr_t ca;

	rc = pthread_condattr_init(&ca);
	assert(rc == 0);

#if defined(CLOCK_MONOTONIC_COARSE)
	*c = CLOCK_MONOTONIC_COARSE;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

#if defined(CLOCK_MONOTONIC_RAW)
	*c = CLOCK_MONOTONIC_RAW;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

#if defined(CLOCK_MONOTONIC_FAST)
	*c = CLOCK_MONOTONIC_FAST;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

#if defined(CLOCK_MONOTONIC)
	*c = CLOCK_MONOTONIC;
	if (clock_gettime(*c, &ts) == 0 &&
	    pthread_condattr_setclock(&ca, *c) == 0)
	{
		res = true;
		goto out;
	}
#endif

out:
	rc = pthread_condattr_destroy(&ca);
	assert(rc == 0);
	return res;
}

bool
fs_get_best_monotonic_clock_gettime(clockid_t *c)
{
	struct timespec ts;

#if defined(CLOCK_MONOTONIC_COARSE)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC_COARSE, &ts))
		return true;
#endif

#if defined(CLOCK_MONOTONIC_RAW)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC_RAW, &ts))
		return true;
#endif

#if defined(CLOCK_MONOTONIC_FAST)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC_FAST, &ts))
		return true;
#endif

#if defined(CLOCK_MONOTONIC)
	if (!clock_gettime((*c) = CLOCK_MONOTONIC, &ts))
		return true;
#endif

	return false;
}

bool
fs_get_best_monotonic_clocks(clockid_t *clkid_gettime,
			     clockid_t *clkid_pthread,
			     char **err)
{
	if (clkid_gettime != NULL && 
	    !fs_get_best_monotonic_clock_gettime(clkid_gettime))
	{
		if (err != NULL)
			*err = my_strdup("no clock available for clock_gettime()");
		return false;
	}

	if (clkid_pthread != NULL &&
	    !fs_get_best_monotonic_clock_pthread(clkid_pthread))
	{
		if (err != NULL)
			*err = my_strdup("no clock available for pthread_cond_timedwait()");
		return false;
	}

	return true;
}

int
fs_pthread_cond_timedwait(clockid_t clock_id,
			  pthread_cond_t *cond,
			  pthread_mutex_t *mutex,
			  unsigned seconds)
{
	int res;
	struct timespec ts;
	res = clock_gettime(clock_id, &ts);
	assert(res == 0);
	ts.tv_sec += seconds;
	return pthread_cond_timedwait(cond, mutex, &ts);
}
