#if !defined(_SMTP_CLIENT_H_)
#define _SMTP_CLIENT_H_

#include <boost/function.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <net/dns_resolver.hpp>
#include <boost/asio/ssl.hpp>

#if defined(HAVE_CONFIG_H)
#include "../config.h"
#endif
#if defined(HAVE_PA_ASYNC_H)
#include <pa/async.h>
#endif

#include "envelope.h"
#include "check.h"
#include "options.h"

class smtp_client:
        public boost::enable_shared_from_this<smtp_client>,
        private boost::noncopyable
{
  public:

    explicit smtp_client(boost::asio::io_service& _io_service);

    typedef boost::function < void () > complete_cb_t;

    void start(const check_data_t& _data,
            complete_cb_t _complete,
            envelope_ptr _envelope,
            const server_parameters::remote_point &_remote,
            const char *_proto_name );

    void stop();

    check_data_t check_data() const { return m_data; }

  protected:

    bool m_lmtp;

    bool m_use_pipelining;

    std::string m_read_buffer;

    complete_cb_t m_complete;

    envelope_ptr m_envelope;

    typedef enum {
        STATE_START = 0,
        STATE_HELLO,
        STATE_AFTER_MAIL,
        STATE_AFTER_RCPT,
        STATE_AFTER_DATA,
        STATE_AFTER_DOT,
        STATE_AFTER_QUIT,
        STATE_ERROR
    } proto_state_t;

    proto_state_t m_proto_state;
    check_data_t m_data;

    std::string m_proto_name;

    boost::asio::ip::tcp::socket m_socket;
    boost::asio::io_service::strand strand_;

    boost::asio::streambuf m_request;
    boost::asio::streambuf m_response;

    void do_stop();

    void start_read_line();

    void handle_read_smtp_line(const boost::system::error_code& _err);

    bool process_answer(std::istream &_stream);

    void handle_connect(const boost::system::error_code& ec, y::net::dns::resolver::iterator);

    void handle_resolve(const boost::system::error_code& ec, y::net::dns::resolver::iterator);

    void handle_write_request(const boost::system::error_code& _err, size_t sz, const std::string& s);

    void handle_write_data_request(const boost::system::error_code& _err, size_t sz);

    y::net::dns::resolver m_resolver;

    void fault(const std::string &_log, const std::string &_remote);

    void success();

    envelope::rcpt_list_t::iterator m_current_rcpt;

    boost::asio::deadline_timer m_timer;

    unsigned int m_timer_value;

    void handle_timer( const boost::system::error_code &_error);

    void restart_timeout();

    check::chk_status report_rcpt(bool _success, const std::string &_log, const std::string &_remote);

    std::string m_line_buffer;

    std::string m_relay_name;
    std::string m_relay_ip;
    int m_relay_port;

    boost::asio::ip::tcp::endpoint m_endpoint;
    void handle_simple_connect(const boost::system::error_code& error);

#if defined(HAVE_PA_ASYNC_H)
    pa::stimer_t m_pa_timer;
#endif

};

typedef boost::shared_ptr<smtp_client> smtp_client_ptr;

#endif // _SMTP_CLIENT_H_
