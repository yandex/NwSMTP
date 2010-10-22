/*
 *	Copyright 1990 by Rayan S. Zachariassen, all rights reserved.
 *	This will be free software, but only when it is finished.
 *
 *	Rewrite for GNU autoconf by  Matti Aarnio <mea@nic.funet.fi> 1996
 */

#include <stdio.h>
#include <memory.h>
#include <time.h>

static const char *weekday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

const char *monthname[] = {	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
				"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

char *
rfc822tz(timep, ts, prettyname, zone_buf, zblen)
	time_t *timep;
	struct tm **ts;
	int prettyname;
	char* zone_buf;
	int zblen;
{
	char *cp;
	int sign, offset;

	*ts    = localtime(timep);
	offset = ((*ts)->tm_gmtoff) / 60;	/* Offset in minutes */

	sign   = offset >= 0;
	if (offset < 0)
	  offset = -offset;

	snprintf(zone_buf, zblen, "%c%02d%02d",
		sign ? '+' : '-', offset / 60, offset % 60);
	cp = zone_buf + strlen(zone_buf);

	if (prettyname)
	  sprintf(cp," (%.19s)",(*ts)->tm_zone);

	return zone_buf;
}

/* Like ctime(), except returns RFC822 format (variable length!) date string */

char* rfc822date(time_t *unixtimep, char* buf, size_t blen, char* zone_buf, size_t zblen)
{
	struct tm *ts;
	rfc822tz(unixtimep, &ts, 0, zone_buf, zblen);

	snprintf(buf, blen, "%s, %d %s %d %02d:%02d:%02d %s\r\n",
		weekday[ts->tm_wday], ts->tm_mday,
		monthname[ts->tm_mon], 1900 + ts->tm_year,
		ts->tm_hour, ts->tm_min, ts->tm_sec, zone_buf);
	return buf;
}
