//
// basic_dns_resolver.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2008 Andreas Haberstroh (andreas at ibusy dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef BOOST_NET_BASIC_DNS_RESOLVER_HPP
#define BOOST_NET_BASIC_DNS_RESOLVER_HPP

#include <net/resolver_iterator.hpp>

namespace y {
namespace net {
namespace dns {

template <typename Service> 
class basic_dns_resolver : public boost::asio::basic_io_object<Service> 
{ 
  public: 

    typedef resolver_iterator iterator;

    explicit basic_dns_resolver(boost::asio::io_service &io_service) 
    : boost::asio::basic_io_object<Service>(io_service) 
    { 
    } 

    void add_nameserver(ip::address addr)
    {
        this->service.add_nameserver(this->implementation, addr);
    }
 
    void set_timeout(int seconds)
    {
        this->service.set_timeout(seconds);
    }

    void set_retries(int count)
    {
        this->service.set_retries(count);
    }

    template<typename Handler>
    void async_resolve(const net::dns::question & question, Handler handler)
    {
        this->service.async_resolve(this->implementation, question, handler);
    }
          
    template<typename Handler>
    void async_resolve(const string & domain, const net::dns::type_t rrtype, Handler handler)
    {
        this->service.async_resolve(this->implementation, domain, rrtype, handler);
    }
          
    void cancel()
    {
        this->service.cancel(this->implementation);
    }
}; 

#if !defined(GENERATING_DOCUMENTATION)
typedef basic_dns_resolver<basic_dns_resolver_service<> > resolver; 
#endif

} // namespace dns
} // namespace net
} // namespace y

#endif // BOOST_NET_BASIC_DNS_RESOLVER_HPP
