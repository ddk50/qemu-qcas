
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <sys/time.h>

#include "bench.h"

static double gettimeofday_sec(void)
{
    struct timeval tv;
    unsigned long msec;
    gettimeofday(&tv, NULL);
    msec = (tv.tv_sec * 1000.0) + (unsigned long)(tv.tv_usec / 1000.0);
    return (double)msec / 1000.0;
}

void settimer(double *g_t1)
{
    *g_t1 = gettimeofday_sec();
}

double stoptimer(double g_t1)
{
    double g_t2 = gettimeofday_sec();
    return (g_t2 - g_t1);
}
