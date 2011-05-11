#if !defined(_SO_CLIENT_H_)
#define _SO_CLIENT_H_

#include <boost/function.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <net/dns_resolver.hpp>
#include <istream>

#if defined(HAVE_CONFIG_H)
#include "../config.h"
#endif
#if defined(HAVE_PA_ASYNC_H)
#include <pa/async.h>
#endif

#include "envelope.h"
#include "check.h"
#include "switchcfg.h"
#include "timer.h"

class so_client:
        public boost::enable_shared_from_this<so_client>,
        private boost::noncopyable
{
  public:

    typedef enum {
        SO_UNKNOWN = 0,
        SO_SKIP = 0,    // Use SO_SKIP instead SO_UNKNOWN
        SO_HAM = 1,
        SO_DELIVERY      = 2,
        SO_SPAM = 4,
        SO_MALICIOUS = 256,
        SO_FAULT = -1
    } spam_status_t;

    explicit so_client(boost::asio::io_service& _io_service, switchcfg *_so_config);

    typedef boost::function < void () > complete_cb_t;

    void start(const check_data_t& _data, complete_cb_t _complete, envelope_ptr _envelope,
            std::string spf_from, boost::optional<std::string> spf_result, boost::optional<std::string> spf_expl);

    void stop();

    check_data_t check_data() const { return m_data; }

  protected:

    void restart();

    std::string m_read_buffer;

    complete_cb_t m_complete;

    envelope_ptr m_envelope;

    unsigned int m_envelope_size;

    typedef enum {
        STATE_START = 0,
        STATE_AFTER_CONNECT,
        STATE_AFTER_HELO,
        STATE_AFTER_MAILFROM,
        STATE_AFTER_RCPTTO,
        STATE_AFTER_DATA,
        STATE_AFTER_DOT,
        STATE_ERROR
    } proto_state_t;

    proto_state_t m_proto_state;

    check_data_t m_data;

    unsigned int m_so_try;

    boost::asio::ip::tcp::socket m_socket;
    boost::asio::io_service::strand strand_;

    boost::asio::streambuf m_request;
    boost::asio::streambuf m_response;

    void do_stop();

    void start_read_line();

    void write_extra_headers();
    void handle_write_extra_headers(const boost::system::error_code& ec);

    void handle_read_so_line(const boost::system::error_code& _err);

    bool process_answer(std::istream &_stream);

    void handle_connect(const boost::system::error_code& ec, y::net::dns::resolver::iterator, int port);

    void handle_resolve(const boost::system::error_code& ec, y::net::dns::resolver::iterator, int port);

    void handle_write_request(const boost::system::error_code& _err);

    y::net::dns::resolver m_resolver;

    void fault(const std::string &_log);

    void success(spam_status_t _status);

    envelope::rcpt_list_t::iterator m_current_rcpt;

    boost::asio::deadline_timer m_timer;

    unsigned int m_timer_value;

    void handle_timer( const boost::system::error_code &_error);

    void restart_timeout();

    switchcfg *m_config;

    std::string m_log_host;
    timer m_log_delay;
    unsigned int m_so_connect_try;

    std::string extra_headers_;

    void log_finish(so_client::spam_status_t _code);

    boost::asio::ip::tcp::endpoint m_endpoint;
    void handle_simple_connect(const boost::system::error_code& error);

#if defined(HAVE_PA_ASYNC_H)
    pa::stimer_t m_pa_timer;
#endif
};

typedef boost::shared_ptr<so_client> so_client_ptr;

#endif // _SO_CLIENT_H_
