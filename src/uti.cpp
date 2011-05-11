#include <iostream>
#include <sstream>
#include <iterator>
#include <algorithm>
#include <boost/format.hpp>

#include "uti.h"

static std::string conv_cr_lf(char _ch)
{
    switch (_ch)
    {
        case '\r':
            return "";
        case '\n':
            return "^M";
        default:
            return std::string(&_ch, 1);
    }
}

std::string cleanup_str(const std::string &_str)
{
    std::string buffer(_str);

    std::string::size_type pos = buffer.find_last_not_of("\r\n");

    if (pos != std::string::npos)
    {
        buffer.erase(pos+1);
    }

    std::ostringstream remote_filt;

    std::transform(buffer.begin(), buffer.end(), std::ostream_iterator<std::string>(remote_filt), conv_cr_lf);

    return remote_filt.str();
}


std::string rev_order_av4_str(const boost::asio::ip::address_v4& a, const std::string& d)
{
    return str(boost::format("%1%.%2%.%3%.%4%.%5%")
            % static_cast<int>(a.to_bytes()[3])
            % static_cast<int>(a.to_bytes()[2])
            % static_cast<int>(a.to_bytes()[1])
            % static_cast<int>(a.to_bytes()[0])
            % d
               );
}

std::string unfqdn(const std::string& fqdn)
{
    std::size_t sz = fqdn.size();
    if (sz && fqdn[sz-1] == '.')
        return std::string(fqdn.begin(), fqdn.begin()+sz-1);
    return fqdn;
}

unsigned long djb2_hash(const unsigned char* str, size_t size)
{
    unsigned long hash = 5381;
    const unsigned char* p, *se = str + size;
    for (p=str; p!=se; ++p)
        hash = ((hash << 5) + hash) ^ *p;
    return hash;
}
