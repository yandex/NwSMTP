#include <config.h>

#ifdef ENABLE_AUTH_BLACKBOX

#include <iostream>
#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "bb_client_auth.h"
#include "log.h"

black_box_client_auth::black_box_client_auth(boost::asio::io_service& _io_service, switchcfg *_switch_cfg):
        m_switch_cfg(_switch_cfg),
        m_io_service(_io_service),
        m_strand(_io_service)
{
}

black_box_client_auth::~black_box_client_auth()
{
}

void black_box_client_auth::start(const auth_info_t &_auth_info, set_status_t _status_cb)
{
    auth_info_ = _auth_info;

#if defined(HAVE_PA_ASYNC_H)
    m_pa_timer.start();
#endif

    m_log_delay.restart();

    m_set_status = _status_cb;
    m_connect_count  = 0;

    m_io_service.post(m_strand.wrap(bind(&black_box_client_auth::restart, shared_from_this())));
}

void black_box_client_auth::restart()
{
    m_connect_count ++;

    if (auth_info_.login_.empty() || auth_info_.password_.empty())
    {
        report(check::CHK_TEMPFAIL, "Call restart before start");
    }

    black_box_parser::field_map f_map;

    f_map["accounts.ena.uid"];
    f_map["subscription.suid.-"];
    f_map["subscription.born_date.-"];
    f_map["subscription.login.-"];
    f_map["subscription.login_rule.-"];

    std::string req;

    server_parameters::remote_point info = (m_connect_count >= g_config.m_bb_try) ? m_switch_cfg->get_secondary() : m_switch_cfg->get_primary();

    std::string login(auth_info_.login_);

    std::string::size_type pos_plus = login.find("+");
    std::string::size_type pos_dog = login.find("@");

    if (pos_plus != std::string::npos)
    {
        if (pos_dog == std::string::npos)
        {
            login = login.substr(0, pos_plus);
        }
        else
        {
            login = login.substr(0, pos_plus) + login.substr(pos_dog, login.length() - pos_dog);
        }
    }

    if (!black_box_parser::format_bb_request(black_box_parser::METHOD_USER_AUTH, info.m_url, login, "smtp", auth_info_.ip_, f_map, false, req))
    {
        report(check::CHK_TEMPFAIL, "Invalid format request line");
    }

    m_http_client.reset(new http_client(m_io_service));

    m_http_client->set_callbacks(m_strand.wrap(boost::bind(&black_box_client_auth::on_error, shared_from_this(), _1, _2)),
            m_strand.wrap(boost::bind(&black_box_client_auth::on_header_read, shared_from_this(), _1)),
            m_strand.wrap(boost::bind(&black_box_client_auth::on_response_read, shared_from_this(), _1, _2))
                                 );

    m_log_host = str(boost::format("%1%:%2%%3%") % info.m_host_name % info.m_port % info.m_url);
    m_black_box_parser.start_parse_request(f_map);

    m_http_client->start(http_client::http_method_put,
            info.m_host_name,
            info.m_port,
            black_box_parser::url_encode(req),
            black_box_parser::url_encode("password=" + auth_info_.password_),
            g_config.m_bb_timeout);
}

void black_box_client_auth::on_error (const boost::system::error_code& ec, const std::string& logemsg)
{
    if (ec == boost::asio::error::operation_aborted)
        return;

    if (m_set_status == NULL)
        return;

    g_log.msg(MSG_NORMAL, str(boost::format("%1%-BB-AUTH: bbauth try=%2%, host='%3%', delay=%4%, stat=error")
                    % auth_info_.session_id_ %  (m_connect_count-1) % m_log_host % timer::format_time(m_log_delay.mark())));

    if (m_connect_count >= g_config.m_bb_try * 2)
    {
        report(check::CHK_TEMPFAIL, "Cannot connect to blackbox:" + logemsg, false);
        return;
    }

    m_io_service.post(m_strand.wrap(bind(&black_box_client_auth::restart, shared_from_this())));
}

void black_box_client_auth::on_header_read(const std::string &_headers)
{
}

void black_box_client_auth::on_response_read(const std::string &_data, bool _eof)
{
    if (!m_black_box_parser.parse_buffer(_data, _eof))
    {
	report(check::CHK_TEMPFAIL, "Error parsing Black Box request");
    }

    if (_eof)
    {
        if (m_black_box_parser.m_has_exception)
        {
            report(check::CHK_TEMPFAIL, m_black_box_parser.m_error_name);
            return;
        }

        unsigned long long int suid = atol(m_black_box_parser.m_field_map["subscription.suid.-"].c_str());

        report(m_black_box_parser.m_auth_success ? check::CHK_ACCEPT : check::CHK_REJECT,
                m_black_box_parser.m_auth_success ? "Success" : m_black_box_parser.m_error_name, suid);
    }
}

void black_box_client_auth::report(const check::chk_status _status, const std::string &_log, unsigned long long _suid, bool _success)
{

    if (m_set_status)
    {
#if defined(HAVE_PA_ASYNC_H)
        pa::async_profiler::add(pa::passport, m_log_host, "blackbox_session", auth_info_.session_id_ + "-AUTH" , m_pa_timer.stop());
#endif

        if (_success)
            g_log.msg(MSG_NORMAL, str(boost::format("%1%-BB-AUTH: bbauth try=%2%, host='%3%', delay=%4%, stat=ok")
                            % auth_info_.session_id_  % (m_connect_count-1) % m_log_host % timer::format_time(m_log_delay.mark())));

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-BB-AUTH: login='%2%', method='%3%', status='%4%'") % auth_info_.session_id_  % auth_info_.login_ % auth_info_.method_ % _log));

        m_io_service.post(boost::bind(m_set_status, _status, _suid));

        m_set_status = NULL;
    }
}

void black_box_client_auth::stop()
{
    m_io_service.post(m_strand.wrap(bind(&black_box_client_auth::do_stop, shared_from_this())));
}

void black_box_client_auth::do_stop()
{
    m_http_client->stop();
    m_http_client.reset(); // http_client shares this; this shares http_client, we need to break this circle here
}

#endif // ENABLE_AUTH_BLACKBOX
