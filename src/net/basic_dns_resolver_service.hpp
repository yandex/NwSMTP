//
// basic_dns_resolver_service.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2008 Andreas Haberstroh (andreas at ibusy dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef BOOST_NET_BASIC_DNS_RESOLVER_SERVICE_HPP
#define BOOST_NET_BASIC_DNS_RESOLVER_SERVICE_HPP

#include <net/dns.hpp>
#include <net/resolver_iterator.hpp>
//#include <boost/thread/thread.hpp>

namespace y {
namespace net {
namespace dns {
  
template <typename DnsResolverImplementation = dns_resolver_impl> 
class basic_dns_resolver_service : public boost::asio::io_service::service 
{ 
  public: 
    static boost::asio::io_service::id id; 

    typedef resolver_iterator iterator;
    
    explicit basic_dns_resolver_service(boost::asio::io_service &io_service) 
    : boost::asio::io_service::service(io_service)
            //          work_(new boost::asio::io_service::work(work_io_service_)), 
            //          work_thread_(boost::bind(&boost::asio::io_service::run, &work_io_service_)) 
    { 
    } 
    
    ~basic_dns_resolver_service() 
    { 
        //          work_.reset(); 
        //          work_io_service_.stop(); 
        //          work_thread_.join(); 
    } 
    
    typedef boost::shared_ptr<DnsResolverImplementation> implementation_type; 
    
    void construct(implementation_type &impl) 
    {
        impl.reset(new DnsResolverImplementation(this->get_io_service())); 
                }

    void destroy(implementation_type &impl)
    {
        if (impl)
            impl->destroy();
        impl.reset();
    } 

    void cancel(implementation_type &impl)
    { 
        if (impl) // ### ?
            impl->cancel(); 
    }

    iterator resolve(implementation_type &impl, const net::dns::question & question)
    {
        return impl->resolve(question);
    }

    iterator resolve(implementation_type &impl, const string & domain, const net::dns::type_t rrtype)
    {
        return impl->resolve(domain, rrtype);
    }
        
    template<typename Handler>
    void async_resolve(implementation_type &impl, const net::dns::question & question, Handler handler)
    {
        impl->async_resolve(question, handler);
    }
          
    template<typename Handler>
    void async_resolve(implementation_type &impl, const string & domain, const net::dns::type_t rrtype, Handler handler)
    {
        net::dns::question question(domain, rrtype);
        impl->async_resolve(question, handler);
    }

    void add_nameserver(implementation_type &impl, ip::address addr)
    {
        impl->add_nameserver(addr);
    }

    void set_timeout(implementation_type &impl, int seconds)
    {
        impl->set_timeout(seconds);
    }

    void set_retries(implementation_type &impl, int count)
    {
        impl->set_retries(count);
    }

    
  private: 
    void shutdown_service() 
    { 
    } 
    
    //        boost::asio::io_service work_io_service_; 
    //        boost::scoped_ptr<boost::asio::io_service::work> work_; 
    //        boost::thread work_thread_; 
}; 
#if !defined(GENERATING_DOCUMENTATION)
template <typename DnsResolverImplementation> 
boost::asio::io_service::id basic_dns_resolver_service<DnsResolverImplementation>::id; 
#endif
} // namespace dns
} // namespace net
} // namespace y

#endif // BOOST_NET_BASIC_DNS_RESOLVER_SERVICE_HPP
