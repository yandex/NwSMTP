#if !defined(_RBL_H_)
#define _RBL_H_

#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/noncopyable.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <net/dns_resolver.hpp>
#include <list>

class rbl_check
        :public boost::enable_shared_from_this<rbl_check>,
         private boost::noncopyable
{
  public:

    rbl_check(boost::asio::io_service& io_service);

    void add_rbl_source(const std::string &_host_name);         // Add rbl source host

    typedef boost::function< void ()> complete_cb;

    void start(const boost::asio::ip::address_v4 &_address, complete_cb _callback);     // Start async check

    void stop();                        // stop all active resolve

    bool get_status(std::string &_message);

  private:

    void handle_resolve(const boost::system::error_code& ec, y::net::dns::resolver::iterator it);

    void start_resolve(const boost::asio::ip::address_v4&, const std::string& d);

    std::list<std::string> m_source_list;

    std::list<std::string>::iterator m_current_source;

    y::net::dns::resolver m_resolver;

    boost::asio::ip::address_v4 m_address;

    complete_cb m_complete;

    std::string m_message;
};

typedef boost::shared_ptr<rbl_check> rbl_client_ptr;

#endif // _RBL_H_
