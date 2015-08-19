#include "ratelimit.h"
#include <time.h>
#include <stdlib.h>

struct rate_limit* init_limit(int burst, time_t period){
	struct rate_limit* limit = (struct rate_limit*)malloc(sizeof(struct rate_limit));
	limit->rate_burst = burst;
	limit->rate_period = period;
	limit->rate_last = time(0);
	limit->rate_count = 0;

	return limit;
}

int check_limit(struct rate_limit* limit, int inc)
{
	time_t now = time(0);

	while((now - limit->rate_last) > limit->rate_period)
	{
		limit->rate_count -= limit->rate_burst;
		limit->rate_count = (limit->rate_count < 0 ? 0 : limit->rate_count);
		limit->rate_last += limit->rate_period;
	}

	if (limit->rate_count < limit->rate_burst){
		limit->rate_count += inc;
		return 1;
	}

	return 0;
}
