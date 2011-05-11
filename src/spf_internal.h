/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of either:
 *
 *   a) The GNU Lesser General Public License as published by the Free
 *      Software Foundation; either version 2.1, or (at your option) any
 *      later version,
 *
 *   OR
 *
 *   b) The two-clause BSD license.
 *
 * These licenses can be found with the distribution in the file LICENSES
 */




#ifndef INC_SPF_INTERNAL
#define INC_SPF_INTERNAL

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#define array_elem(x) ((long int)(sizeof( x ) / sizeof( *x )))


/*
 * misc macros to make the code look cleaner than it really is
 */

#ifndef SPF_MAX_DNS_MECH
/**
 * It is a bad idea to change this for two reasons.
 *
 * First, the obvious reason is the delays caused on the mail server
 * you are running.  DNS lookups that timeout can be *very* time
 * consuming, and even successful DNS lookups can take 200-500ms.
 * Many MTAs can't afford to wait long and even 2sec is pretty bad.
 *
 * The second, and more important reason, is the SPF records come from
 * a third party which may be malicious.  This third party can direct
 * DNS lookups to be sent to anyone.  If there isn't a limit, then it
 * is easy for someone to create a distributed denial of service
 * attack simply by sending a bunch of emails.  Unlike the delays on
 * your system caused by many DNS lookups, you might not even notice
 * that you are being used as part of a DDoS attack.
 */
#define SPF_MAX_DNS_MECH 10
#endif
#ifndef SPF_MAX_DNS_PTR
/**
 * It is a bad idea to change this for the same reasons as mentioned
 * above for SPF_MAX_DNS_MECH
 */
#define SPF_MAX_DNS_PTR   10
#endif
#ifndef SPF_MAX_DNS_MX
/**
 * It is a bad idea to change this for the same reasons as mentioned
 * above for SPF_MAX_DNS_MECH
 */
#define SPF_MAX_DNS_MX    10
#endif

#if 1
#define _ALIGN_SZ       4
static inline size_t _align_sz(size_t s)
{ return (s + (_ALIGN_SZ - 1 - (((s - 1) & (_ALIGN_SZ - 1))))); }
static inline char * _align_ptr(char *s)
{ return (s + (_ALIGN_SZ - 1 - ((((size_t)s - 1) & (_ALIGN_SZ - 1))))); }
#else
static inline size_t _align_sz(size_t s) { return s; }
static inline char * _align_ptr(char *s) { return s; }
#endif

#include <spf2/spf_record.h>

/* FIXME: need to make these network/compiler portable  */
/* FIXME: Several of these duplicate each other. Bad. */
static inline size_t SPF_mech_data_len( SPF_mech_t * mech )
{ return (mech->mech_type == MECH_IP4)
            ? sizeof( struct in_addr )
            : (mech->mech_type == MECH_IP6)
            ? sizeof( struct in6_addr )
            : mech->mech_len; }
static inline SPF_mech_t *SPF_mech_next( SPF_mech_t * mech )
{ return (SPF_mech_t *)_align_ptr(
    (char *)mech + sizeof(SPF_mech_t) + SPF_mech_data_len( mech )
    ); }
static inline SPF_data_t *SPF_mech_data( SPF_mech_t *mech )
{ return (SPF_data_t *)( (char *)mech + sizeof(SPF_mech_t)); }
static inline SPF_data_t *SPF_mech_end_data( SPF_mech_t *mech )
{ return (SPF_data_t *)( (char *)SPF_mech_data(mech) +
            SPF_mech_data_len( mech ));}
static inline struct in_addr *SPF_mech_ip4_data( SPF_mech_t *mech )
{ return (struct in_addr *)( (char *)mech + sizeof(SPF_mech_t)); }
static inline struct in6_addr *SPF_mech_ip6_data( SPF_mech_t *mech )
{ return (struct in6_addr *)( (char *)mech + sizeof(SPF_mech_t)); }

static inline size_t SPF_data_len( SPF_data_t *data )
{ return sizeof(SPF_data_t) +
            (data->ds.parm_type == PARM_STRING ? data->ds.len : 0); }
static inline SPF_data_t *SPF_data_next( SPF_data_t *data )
{ return (SPF_data_t *)_align_ptr(
    (char *)data + SPF_data_len(data)
    ); }
static inline char *SPF_data_str( SPF_data_t *data )
{ return (char *)data + sizeof(SPF_data_t); }

static inline size_t SPF_mod_len( SPF_mod_t *mod )
{ return _align_sz(sizeof(SPF_mod_t) + mod->name_len) + mod->data_len; }
static inline SPF_mod_t *SPF_mod_next( SPF_mod_t *mod )
{ return (SPF_mod_t *)_align_ptr(
    (char *)mod + SPF_mod_len(mod)
    ); }
static inline char *SPF_mod_name( SPF_mod_t *mod )
{ return (char *)mod + sizeof(SPF_mod_t); }
static inline SPF_data_t *SPF_mod_data( SPF_mod_t *mod )
{ return (SPF_data_t *)_align_ptr(
    (char *)mod + sizeof(SPF_mod_t) + mod->name_len
    ); }
static inline SPF_data_t *SPF_mod_end_data( SPF_mod_t *mod )
{ return (SPF_data_t *)((char *)SPF_mod_data(mod) + mod->data_len); }

static inline size_t SPF_macro_data_len( SPF_macro_t * mac )
{ return mac->macro_len; }
static inline SPF_data_t *SPF_macro_data( SPF_macro_t * mac )
{ return (SPF_data_t *)( (char *)mac + sizeof(SPF_macro_t)); }


char *SPF_sanitize( SPF_server_t *spf_server, char *str );

void SPF_print_sizeof(void);

SPF_errcode_t SPF_realloc(char **bufp, size_t *buflenp, int buflen);


/**
 * A wrapper for reporting errors from sub-functions.
 *   SPF_errcode_t foo(int a) { ... }
 * becomes:
 *   SPF_WRAP_FUNCTION(SPF_foo, (int a), (a)) { .... }
 * As yet unused.
 */
#define SPF_WRAP_FUNCTION(name, proto, args)    \
    SPF_errcode_t name proto {                  \
        SPF_errcode_t err = name ## _real args; \
        SPF_debug(#name " returns %d\n", err);  \
        return err;                             \
    }                                           \
    SPF_errcode_t name ## _real proto

#endif
