#ifndef RFC822DATE_H
#define RFC822DATE_H

extern "C" char* rfc822date(time_t *unixtimep, char* buf, size_t blen, char* zone_buf, size_t zblen);

#endif // RFC822DATE_H
