#include <config.h>

#ifdef ENABLE_AUTH_BLACKBOX

#include <iostream>
#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "bb_client_mailfrom.h"
#include "log.h"

black_box_client_mailfrom::black_box_client_mailfrom(boost::asio::io_service& _io_service, switchcfg *_switch_cfg):
        m_switch_cfg(_switch_cfg),
        m_io_service(_io_service),
        m_strand(_io_service)
{
}

black_box_client_mailfrom::~black_box_client_mailfrom()
{
}

void black_box_client_mailfrom::start(const black_box_client_mailfrom::mailfrom_info_t &_mailfrom_info, set_status_t _status_cb)
{
    mailfrom_info_ = _mailfrom_info;

#if defined(HAVE_PA_ASYNC_H)
    m_pa_timer.start();
#endif

    m_log_delay.restart();

    m_set_status = _status_cb;
    m_connect_count  = 0;

    m_io_service.post(m_strand.wrap(bind(&black_box_client_mailfrom::restart, shared_from_this())));
}

void black_box_client_mailfrom::restart()
{
    m_connect_count ++;

    if (mailfrom_info_.mailfrom_.empty())
    {
        report(check::CHK_REJECT, "503 5.5.4 Error: requires non-null sender", black_box_client_mailfrom::mailfrom_optional_result_t());
    }

    black_box_parser::field_map f_map;

    f_map["accounts.ena.uid"];
    f_map["subscription.suid.-"];
    f_map["subscription.born_date.-"];
    f_map["subscription.login.-"];
    f_map["subscription.login_rule.-"];

    std::string req;

    server_parameters::remote_point info = (m_connect_count >= g_config.m_bb_try) ? m_switch_cfg->get_secondary() : m_switch_cfg->get_primary();

    if (!black_box_parser::format_bb_request(black_box_parser::METHOD_USER_INFO, info.m_url, mailfrom_info_.mailfrom_, "smtp", mailfrom_info_.ip_, f_map, false, req))
    {
        report(check::CHK_TEMPFAIL, "Invalid format request line", black_box_client_mailfrom::mailfrom_optional_result_t());
    }

    m_http_client.reset(new http_client(m_io_service));

    m_http_client->set_callbacks(m_strand.wrap(boost::bind(&black_box_client_mailfrom::on_error, shared_from_this(), _1, _2)),
            m_strand.wrap(boost::bind(&black_box_client_mailfrom::on_header_read, shared_from_this(), _1)),
            m_strand.wrap(boost::bind(&black_box_client_mailfrom::on_response_read, shared_from_this(), _1, _2))
                                 );

    m_log_host = str(boost::format("%1%:%2%%3%") % info.m_host_name % info.m_port % info.m_url);
    m_black_box_parser.start_parse_request(f_map);

    m_http_client->start(http_client::http_method_get,
            info.m_host_name,
            info.m_port,
            black_box_parser::url_encode(req),
            "",
            g_config.m_bb_timeout);
}

void black_box_client_mailfrom::on_error (const boost::system::error_code& ec, const std::string& logemsg)
{
    if (ec == boost::asio::error::operation_aborted)
        return;

    if (m_set_status == NULL)
        return;

    g_log.msg(MSG_NORMAL, str(boost::format("%1%-BB-MAILFROM: bbauth try=%2%, host='%3%', delay=%4%, stat=error")
                    % mailfrom_info_.session_id_ %  (m_connect_count-1) % m_log_host % timer::format_time(m_log_delay.mark())));

    if (m_connect_count >= g_config.m_bb_try * 2)
    {
        report(check::CHK_TEMPFAIL, "Cannot connect to blackbox:" + logemsg, black_box_client_mailfrom::mailfrom_optional_result_t(), false);
        return;
    }

    m_io_service.post(m_strand.wrap(bind(&black_box_client_mailfrom::restart, shared_from_this())));
}

void black_box_client_mailfrom::on_header_read(const std::string &_headers)
{
}

void black_box_client_mailfrom::on_response_read(const std::string &_data, bool _eof)
{

    if (!m_black_box_parser.parse_buffer(_data, _eof))
    {
	report(check::CHK_TEMPFAIL, "Error parsing Black Box request", black_box_client_mailfrom::mailfrom_optional_result_t());
    }

    if (_eof)
    {
        if (m_black_box_parser.m_has_exception)
        {
            report(check::CHK_TEMPFAIL, m_black_box_parser.m_error_name, black_box_client_mailfrom::mailfrom_optional_result_t());
            return;
        }

        black_box_client_mailfrom::mailfrom_result_t res;

        res.suid_ = atol(m_black_box_parser.m_field_map["subscription.suid.-"].c_str());
        res.karma_ = m_black_box_parser.m_karma;
        res.karma_status_ = m_black_box_parser.m_karma_status;
	res.time_stamp_ = atol(m_black_box_parser.m_field_map["subscription.born_date.-"].c_str());
	res.auth_addr_ = mailfrom_info_.mailfrom_;

        report( check::CHK_ACCEPT, "Success", black_box_client_mailfrom::mailfrom_optional_result_t(res) );
    }
}

void black_box_client_mailfrom::report(check::chk_status _status,  const std::string &_log, black_box_client_mailfrom::mailfrom_optional_result_t _result, bool _success)
{

    if (m_set_status)
    {
#if defined(HAVE_PA_ASYNC_H)
        pa::async_profiler::add(pa::passport, m_log_host, "blackbox_session", mailfrom_info_.session_id_ + "-AUTH" , m_pa_timer.stop());
#endif

        if (_success)
            g_log.msg(MSG_NORMAL, str(boost::format("%1%-BB-MAILFROM: bbauth try=%2%, host='%3%', delay=%4%, stat=ok")
                            % mailfrom_info_.session_id_  % (m_connect_count-1) % m_log_host % timer::format_time(m_log_delay.mark())));

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-BB-MAILFROM: mailfrom='%2%', status='%3%'") % mailfrom_info_.session_id_  % mailfrom_info_.mailfrom_ % _log));

	if (_result)
	{
    	    m_io_service.post(boost::bind(m_set_status, _status, _result.get()));
	}
	else
	{
	    m_io_service.post(boost::bind(m_set_status, _status, black_box_client_mailfrom::mailfrom_result_t()));	// empty object
	}

        m_set_status = NULL;
    }
}

void black_box_client_mailfrom::stop()
{
    m_io_service.post(m_strand.wrap(bind(&black_box_client_mailfrom::do_stop, shared_from_this())));
}

void black_box_client_mailfrom::do_stop()
{
    m_http_client->stop();
    m_http_client.reset(); // http_client shares this; this shares http_client, we need to break this circle here
}

#endif // ENABLE_AUTH_BLACKBOX
