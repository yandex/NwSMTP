#if !defined(_BB_CLIENT_MAILFROM_H_)
#define _BB_CLIENT_MAILFROM_H_

#ifdef ENABLE_AUTH_BLACKBOX

#include <string>
#include <map>
#include <expat.h>
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
#include "bb_parser.h"
#include "timer.h"

class black_box_client_mailfrom:
        public boost::enable_shared_from_this<black_box_client_mailfrom>,
        private boost::noncopyable

{
  public:

    typedef struct
    {
        std::string session_id_;
        std::string mailfrom_;
        std::string ip_;
    } mailfrom_info_t;

    typedef struct
    {
	unsigned long long int suid_;
	int karma_;
	int karma_status_;
	time_t time_stamp_;
	std::string auth_addr_;
    } mailfrom_result_t;

    typedef boost::optional<black_box_client_mailfrom::mailfrom_result_t> mailfrom_optional_result_t;

    black_box_client_mailfrom(boost::asio::io_service& io_service, switchcfg *_switch_cfg);

    ~black_box_client_mailfrom();

    typedef boost::function< void (check::chk_status _status, mailfrom_result_t _auth_result) > set_status_t;

    void start(const mailfrom_info_t &_mailfrom_info, set_status_t _status_cb);

    void stop();

    check_rcpt_t check_rcpt() const;

  protected:

    void report(check::chk_status _status, const std::string &_log, mailfrom_optional_result_t _result, bool _success = true);         // end check process

    void do_stop();
    void restart();                                                             // new BB request
    void on_error (const boost::system::error_code& ec, const std::string& logemsg);
    void on_header_read(const std::string &_headers);
    void on_response_read(const std::string &_data, bool _eof);

    black_box_parser m_black_box_parser;

    http_client_ptr m_http_client;

    switchcfg *m_switch_cfg;

    unsigned int m_connect_count;

    boost::asio::io_service &m_io_service;

    set_status_t m_set_status;

    std::string m_log_host;

    timer m_log_delay;

#if defined(HAVE_PA_ASYNC_H)
    pa::stimer_t m_pa_timer;
#endif

    boost::asio::io_service::strand m_strand;

    mailfrom_info_t mailfrom_info_;
};

typedef boost::shared_ptr<black_box_client_mailfrom> black_box_client_mailfrom_ptr;

#endif // ENABLE_AUTH_BLACKBOX

#endif //_BB_CLIENT_MAILFROM_H_
