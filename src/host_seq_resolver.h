#ifndef NWSMTP_HOST_SEQ_RESOLVER_H
#define NWSMTP_HOST_SEQ_RESOLVER_H

#include <iterator>
#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <net/dns_resolver.hpp>
#include <deque>

// Host resolver intented to check hosts in config options
/*
 * Preconditions:
 * 1. Endpoint(std::string(), int()) should be a valid expression convertible to OutIter::value_type
 * 2. InIter models input iterator
 * 3. OutIter models output iterator (may be singular)
 * 4. OutIter::value_type should be default constructible
 */
template <typename Endpoint, typename InIter, typename OutIter>
class host_sequence_resolver
{
    boost::asio::io_service ios_;
    y::net::dns::resolver r_;
    boost::asio::io_service::strand strand_;

    typedef std::deque<Endpoint> deque_t;
    class resolver
    {
      public:
        InIter src_;
        typename deque_t::iterator dst_;
        int port_;

        resolver(InIter src, typename deque_t::iterator dst, int port)
                : src_(src),
                  dst_(dst),
                  port_(port)
        {
        }

        void operator()(const boost::system::error_code& ec,
                y::net::dns::resolver::iterator it)
        {
            if (ec)
                throw std::runtime_error( str(boost::format("failed to resolve %1%") % *src_) );

            if (const boost::shared_ptr<y::net::dns::a_resource> ar =
                    boost::dynamic_pointer_cast<y::net::dns::a_resource>(*it))
            {
                *dst_++ =  Endpoint(ar->address(), port_);
                return;
            }
        }
    };

  public:
    host_sequence_resolver()
            : ios_(),
              r_(ios_),
              strand_(ios_)
    {
    }

    void  operator()(InIter ibeg, InIter iend, OutIter dst, int port)
    {
        deque_t d;
        for (; ibeg != iend; ++ibeg)
        {
            d.push_back(typename deque_t::value_type());
            typename deque_t::iterator dst = --d.end();
            try
            {
                // See if resolving is really needed
                Endpoint e(boost::asio::ip::address_v4::from_string(*ibeg), port);
                *dst++ = e;
                continue;
            }
            catch (...) {}

            r_.async_resolve(*ibeg, y::net::dns::type_a,
                    strand_.wrap(resolver(ibeg, dst, port)));
        }

        ios_.run();
        std::copy(d.begin(), d.end(), dst);
    }
};

template <typename Endpoint, typename In, typename Out>
void resolve_host_sequence(In ibeg, In iend, Out out, int port)
{
    host_sequence_resolver<Endpoint, In, Out> r;
    r(ibeg, iend, out, port);
}

#endif //  NWSMTP_HOST_SEQ_RESOLVER_H
