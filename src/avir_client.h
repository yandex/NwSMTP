#if !defined(_AVIR_CLIENT_H_)
#define _AVIR_CLIENT_H_

#include <boost/function.hpp>
#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <net/dns_resolver.hpp>

#if defined(HAVE_CONFIG_H)
#include "../config.h"
#endif
#if defined(HAVE_PA_ASYNC_H)
#include <pa/async.h>
#endif

#include "check.h"
#include "switchcfg.h"
#include "envelope.h"

class avir_client:
        public boost::enable_shared_from_this<avir_client>,
        private boost::noncopyable
{
  public:
    avir_client(boost::asio::io_service& io_service, switchcfg *_config);

    typedef boost::function < void () > complete_cb_t;

    void start(const check_data_t& _data, complete_cb_t complete_cb, envelope_ptr _envelope);

    void stop();

    check_data_t check_data() const { return m_data; }

  protected:
    void do_stop();

    void restart();

    void handle_connect(const boost::system::error_code& ec, y::net::dns::resolver::iterator, int port);
    void handle_resolve(const boost::system::error_code& ec, y::net::dns::resolver::iterator, int port);
    void handle_write_prolog(const boost::system::error_code& _err);
    void handle_write_request(const boost::system::error_code &_err);
    void handle_read_status(const boost::system::error_code& _e,  std::size_t _bytes_transferred);
    void handle_read_code(const boost::system::error_code& _e,  std::size_t _bytes_transferred);

    void fault(const std::string &_log);
    void success(bool _infected);

    y::net::dns::resolver m_resolver;
    boost::asio::ip::tcp::socket m_socket;
    boost::asio::io_service::strand strand_;

    boost::asio::streambuf m_request;
    boost::array<uint32_t, 8192> m_buffer;

    check_data_t m_data;
    envelope_ptr m_envelope;
    complete_cb_t m_complete;

    switchcfg *m_config;
    unsigned int m_try;
    std::size_t m_envelope_size;

    boost::asio::deadline_timer m_timer;

    unsigned int m_timer_value;

    void handle_timer( const boost::system::error_code &_error);
    void restart_timeout();

    std::string m_log_host;
    bool m_log_connect;
    bool m_log_check;
    timer m_log_delay;

    void log_try(const std::string &_status, const std::string &_log);

#if defined(HAVE_PA_ASYNC_H)
    pa::stimer_t m_pa_timer;
#endif
};

typedef boost::shared_ptr<avir_client> avir_client_ptr;

#endif // _AVIR_CLIENT_H_
