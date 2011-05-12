#ifndef GREYLISTING_H
#define GREYLISTING_H

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>
#include <boost/range.hpp>
#include "buffers.h"
#include "greylisting_options.h"
#include "basic_rc_client.h"

class greylisting_client
        : public boost::enable_shared_from_this<greylisting_client>
{
  public:
    typedef ystreambuf::const_buffers_type yconst_buffers;
    typedef ybuffers_iterator<yconst_buffers> yconst_buffers_iterator;
    typedef boost::iterator_range<yconst_buffers_iterator> iter_range_t;
    typedef std::vector<boost::asio::ip::udp::endpoint> hostlist;

    enum errors
    {
        too_early = 1,
        too_late,
        logical_error
    };

    struct headers
    {
        iter_range_t to;
        iter_range_t from;
        iter_range_t messageid;
        iter_range_t subject;
        iter_range_t date;
    };
    struct key
    {
        boost::asio::ip::address client_ip;
        std::string envelope_from;
        std::string envelope_to;
        headers h;
        iter_range_t body;
        key( const boost::asio::ip::address& ip,  const std::string& smtp_from,
                const std::string& smtp_to,  const headers& hs, const iter_range_t& b)
                : client_ip(ip),
                  envelope_from(smtp_from),
                  envelope_to(smtp_to),
                  h(hs),
                  body(b)
        {}
    };

    struct info_t // result of greylisting probing
    {
        std::size_t keyhash;
        boost::asio::ip::udp::endpoint host;
        std::string suid;
        long long int age; // age of the key
        int n;   // total number of marks for the key specified
        int m;   // number of successful marks for the key specified
        bool passed; // wether greylisting check passed
        bool valid;  // wether contents of this struct make any sense (depends on the probe completion status)

        info_t()
                : keyhash(0),
                  host(),
                  suid(),
                  age(0),
                  n(0),
                  m(0),
                  passed(false),
                  valid(false)
        {
        }
    };

    greylisting_client(boost::asio::io_service& ios,
            const greylisting_options& opt,
            const hostlist& list);

    typedef boost::function< void(const boost::system::error_code&, hostlist::value_type) > handler_t;

    // Start asynchronous greylisting check; issues a 'get' request
    void probe(const key& i, const std::string& comment, handler_t handler);

    // Get the result of the last probe() compeletion
    const info_t& info() const { return i_; }

    // Issues an asynchronous 'add' request using the result of the last probe() completion
    void mark(const std::string& comment, handler_t handler);

    // Stop the last request
    void stop();

  private:
    class request;
    typedef boost::function<void(const boost::system::error_code&,
            boost::shared_ptr<greylisting_client::request>) > request_handler_t;

    void handle_probe(const boost::system::error_code& ec, boost::shared_ptr<request> req);
    void handle_mark(const boost::system::error_code& ec, boost::shared_ptr<request> req);

    const greylisting_options& opt_;
    const hostlist& l_;
    basic_rc_client<request> cl_;
    info_t i_;
};

const boost::system::error_category& get_gr_category();

static const boost::system::error_category& gr_category = get_gr_category();

inline boost::system::error_code make_error_code(greylisting_client::errors e)
{
    return boost::system::error_code(
        static_cast<int>(e), gr_category);
}

namespace boost { namespace system {
template<> struct is_error_code_enum<greylisting_client::errors>
{
  static const bool value = true;
};
}}

#endif // GREYLISTING_H
