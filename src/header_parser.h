#ifndef _HEADER_PARSER_H_
#define _HEADER_PARSER_H_

#include "envelope.h"
#include <boost/range/iterator_range.hpp>
#include <boost/function.hpp>

typedef boost::iterator_range<envelope::yconst_buffers_iterator> header_iterator_range_t;
typedef boost::function< void (const header_iterator_range_t& name, const header_iterator_range_t& header,
        const header_iterator_range_t& value) > header_callback_t;

header_iterator_range_t::iterator parse_header(header_iterator_range_t header, header_callback_t callback);

#endif //_EOM_PARSER_H_
