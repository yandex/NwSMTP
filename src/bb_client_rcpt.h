#if !defined(_BB_CLIENT_RCPT_H_)
#define _BB_CLIENT_RCPT_H_

#ifdef ENABLE_AUTH_BLACKBOX

#include <string>
#include <boost/noncopyable.hpp>
#include <boost/enable_shared_from_this.hpp>

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#if defined(HAVE_PA_ASYNC_H)
#include <pa/async.h>
#endif

#include "http_client.h"
#include "switchcfg.h"
#include "check.h"
#include "envelope.h"
#include "bb_parser.h"

class black_box_client_rcpt:
        public boost::enable_shared_from_this<black_box_client_rcpt>,
        private boost::noncopyable

{
  public:

    black_box_client_rcpt(boost::asio::io_service& io_service, switchcfg *_switch_cfg);

    ~black_box_client_rcpt();

    typedef boost::function< void () > set_rcpt_status_t;

    void start(const check_rcpt_t& _rcpt, set_rcpt_status_t _status_cb, envelope_ptr _envelope);

    void stop();

    check_rcpt_t check_rcpt() const;

  protected:

    void report(const std::string &_response, const std::string &_log, bool success = true);    // end check process

    void do_stop();
    void restart();                                                             // new BB request
    void on_error (const boost::system::error_code& ec, const std::string& logemsg);
    void on_header_read(const std::string &_headers);
    void on_response_read(const std::string &_data, bool _eof);

    black_box_parser m_black_box_parser;

    http_client_ptr m_http_client;

    check_rcpt_t m_check_rcpt;

    switchcfg *m_switch_cfg;

    unsigned int m_connect_count;

    boost::asio::io_service &m_io_service;

    set_rcpt_status_t m_set_rcpt_status;

    envelope_ptr  m_envelope;

    std::string m_log_host;

    timer m_log_delay;

#if defined(HAVE_PA_ASYNC_H)
    pa::stimer_t m_pa_timer;
#endif

    boost::asio::io_service::strand m_strand;
};

typedef boost::shared_ptr<black_box_client_rcpt> black_box_client_rcpt_ptr;

#endif // ENABLE_AUTH_BLACKBOX

#endif //_BB_CLIENT_H_
