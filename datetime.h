
#ifndef __DATETIME_H__
#define __DATETIME_H__

#include "qemu-common.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>

int parse_datetime(const char *s, time_t *ret_time);

#endif
