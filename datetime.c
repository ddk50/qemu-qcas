
#include "datetime.h"

int parse_datetime(const char *s, time_t *ret_time)
{
    struct tm tm;
    time_t time;
    int ret = 0;

    fprintf(stderr, 
            "%s: %s\n",
            __FUNCTION__, (char*)s);

    // 2013:18:00T12:30:20
    if (sscanf(s, "%d-%d-%dT%d:%d:%d",
               &tm.tm_year,
               &tm.tm_mon,
               &tm.tm_mday,
               &tm.tm_hour,
               &tm.tm_min,
               &tm.tm_sec) == 6) {
      /* OK */
    } else if (sscanf(s, "%d-%d-%d",
                      &tm.tm_year,
                      &tm.tm_mon,
                      &tm.tm_mday) == 3) {
        tm.tm_hour = 0;
        tm.tm_min = 0;
        tm.tm_sec = 0;
    } else {
        goto fail;
    }
   
    fprintf(stderr, 
            "%s debug: %04d-%02d-%02d %02d:%02d:%02d\n",
            __FUNCTION__,
            tm.tm_year,
            tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec);

    tm.tm_year -= 1900;
    tm.tm_mon--;

    time = mktime(&tm);
    if (time < 0) {
        goto fail;
    }
    *ret_time = time;
    ret = 1;

fail:
    return ret;
}
