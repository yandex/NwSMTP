#include <string>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "rfc_date.h"

#define DAY_MIN         (24 * HOUR_MIN) /* minutes in a day */
#define HOUR_MIN        60              /* minutes in an hour */
#define MIN_SEC         60              /* seconds in a minute */

#define STRFTIME_FMT "%a, %e %b %Y %H:%M:%S "

std::string mail_date(time_t when)
{
    std::string collect;

    struct tm *lt;
    struct tm gmt;
    int     gmtoff;

    gmt = *gmtime(&when);
    lt = localtime(&when);

    gmtoff = (lt->tm_hour - gmt.tm_hour) * HOUR_MIN + lt->tm_min - gmt.tm_min;
    if (lt->tm_year < gmt.tm_year)
        gmtoff -= DAY_MIN;
    else if (lt->tm_year > gmt.tm_year)
        gmtoff += DAY_MIN;
    else if (lt->tm_yday < gmt.tm_yday)
        gmtoff -= DAY_MIN;
    else if (lt->tm_yday > gmt.tm_yday)
        gmtoff += DAY_MIN;
    if (lt->tm_sec <= gmt.tm_sec - MIN_SEC)
        gmtoff -= 1;
    else if (lt->tm_sec >= gmt.tm_sec + MIN_SEC)
        gmtoff += 1;


    char buffer[100];

    memset(buffer, 0, sizeof(buffer));

    strftime(buffer, sizeof(buffer)-1, STRFTIME_FMT, lt);

    collect = buffer;

    if (gmtoff < -DAY_MIN || gmtoff > DAY_MIN)
    {
        // error
    }

    memset(buffer, 0, sizeof(buffer));

    snprintf(buffer, sizeof(buffer)-1, "%+03d%02d", (int) (gmtoff / HOUR_MIN), (int) (abs(gmtoff) % HOUR_MIN));

    collect.append(buffer);

    memset(buffer, 0, sizeof(buffer));

    strftime(buffer, sizeof(buffer)-1, " (%Z)", lt);

    return collect;
}
