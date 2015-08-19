#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <time.h>

struct rate_limit{
	int rate_burst;
	time_t rate_period;
	time_t rate_last;
	long rate_count;
};

struct rate_limit* init_limit(int burst, time_t period);
int check_limit(struct rate_limit* limit, int inc);

#endif
