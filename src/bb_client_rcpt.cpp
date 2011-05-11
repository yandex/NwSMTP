#include <config.h>

#ifdef ENABLE_AUTH_BLACKBOX

#include <iostream>
#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "bb_client_rcpt.h"
#include "log.h"

black_box_client_rcpt::black_box_client_rcpt(boost::asio::io_service& _io_service, switchcfg *_switch_cfg):
        m_switch_cfg(_switch_cfg),
        m_io_service(_io_service),
        m_strand(_io_service)
{
}

black_box_client_rcpt::~black_box_client_rcpt()
{
}

void black_box_client_rcpt::start(const check_rcpt_t& _rcpt, set_rcpt_status_t _status_cb, envelope_ptr _envelope)
{
    m_check_rcpt = _rcpt;

#if defined(HAVE_PA_ASYNC_H)
    m_pa_timer.start();
#endif

    m_log_delay.restart();

    m_envelope = _envelope;
    m_set_rcpt_status = _status_cb;
    m_check_rcpt = _rcpt;
    m_connect_count  = 0;

    m_io_service.post(m_strand.wrap(bind(&black_box_client_rcpt::restart, shared_from_this())));
}

check_rcpt_t black_box_client_rcpt::check_rcpt() const
{
    return m_check_rcpt;
}

void black_box_client_rcpt::restart()
{
    m_connect_count ++;

    if (m_check_rcpt.m_rcpt.empty())
    {
        report(temp_user_error, "Call restart before start");
    }

    black_box_parser::field_map f_map;

    f_map["account_info.reg_date.uid"];
    f_map["subscription.suid.-"];
    f_map["subscription.born_date.-"];
    f_map["subscription.login.-"];
    f_map["subscription.login_rule.-"];
    f_map["accounts.ena.uid"];

    std::string req;

    server_parameters::remote_point info = (m_connect_count >= g_config.m_bb_try) ? m_switch_cfg->get_secondary() : m_switch_cfg->get_primary();

    std::string rcpt(m_check_rcpt.m_rcpt);

    std::string::size_type pos_plus = rcpt.find("+");
    std::string::size_type pos_dog = rcpt.find("@");

    if (pos_plus != std::string::npos)
    {
        if (pos_dog == std::string::npos)
        {
            rcpt = rcpt.substr(0, pos_plus);
        }
        else
        {
            rcpt = rcpt.substr(0, pos_plus) + rcpt.substr(pos_dog, rcpt.length() - pos_dog);
        }
    }

    if (!black_box_parser::format_bb_request(black_box_parser::METHOD_USER_INFO, info.m_url, rcpt, "smtp", m_check_rcpt.m_remote_ip, f_map, false, req))
    {
        report(temp_user_error, "Invalid format request line");
    }

    m_http_client.reset(new http_client(m_io_service));

    m_http_client->set_callbacks(m_strand.wrap(boost::bind(&black_box_client_rcpt::on_error, shared_from_this(), _1, _2)),
            m_strand.wrap(boost::bind(&black_box_client_rcpt::on_header_read, shared_from_this(), _1)),
            m_strand.wrap(boost::bind(&black_box_client_rcpt::on_response_read, shared_from_this(), _1, _2))
                                 );

    m_log_host = str(boost::format("%1%:%2%%3%") % info.m_host_name % info.m_port % info.m_url);
    m_black_box_parser.start_parse_request(f_map);

    m_http_client->start(http_client::http_method_get, info.m_host_name, info.m_port, black_box_parser::url_encode(req), "",  g_config.m_bb_timeout);
}

void black_box_client_rcpt::on_error (const boost::system::error_code& ec, const std::string& logemsg)
{
    if (ec == boost::asio::error::operation_aborted)
        return;

    if (m_set_rcpt_status == NULL)
        return;

    g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-BB: bbatt try=%3%, host='%4%', delay=%5%, stat=error")
                    % m_check_rcpt.m_session_id %  m_envelope->m_id % (m_connect_count-1) % m_log_host % timer::format_time(m_log_delay.mark())));

    if (m_connect_count >= g_config.m_bb_try * 2)
    {
        report(temp_user_error, "Cannot connect to blackbox:" + logemsg, false);
        return;
    }

    m_io_service.post(m_strand.wrap(bind(&black_box_client_rcpt::restart, shared_from_this())));
}

void black_box_client_rcpt::on_header_read(const std::string &_headers)
{
}

void black_box_client_rcpt::on_response_read(const std::string &_data, bool _eof)
{
    if (!m_black_box_parser.parse_buffer(_data, _eof))
    {
	on_error( boost::system::error_code() , "Error parsing Black Box request");
    }

    if (_eof)
    {
        if (m_black_box_parser.m_has_exception)
        {
            on_error( boost::system::error_code() , m_black_box_parser.m_error_name);
            return;
        }

        try
        {
            m_check_rcpt.m_suid = atol(m_black_box_parser.m_field_map["subscription.suid.-"].c_str());
        }
        catch(...)
        {
            // no suid found
        }

        if (m_black_box_parser.m_uid.empty() || m_black_box_parser.m_uid == "\n" || m_black_box_parser.m_uid == "\r\n")
        {

            try
            {
                if (!m_black_box_parser.m_field_map["subscription.login.-"].empty())
                {
                    report("250 Ok", "Success (aliases)");
                    return;
                }
                // user not found
            }
            catch(...)
            {
                // user not found
            }

            report("550 5.7.1 No such user!", "User not found !");
            return;
        }

        time_t now;
        time(&now);

        m_check_rcpt.m_uid = m_black_box_parser.m_uid;

        if (((unsigned)atoll(m_black_box_parser.m_uid.c_str())) < g_no_spam_uid)
        {
            report("250 Ok", "Success");
            return;
        }

        try
        {

            if ((m_black_box_parser.m_field_map["accounts.ena.uid"] == "0") || (m_black_box_parser.m_field_map["subscription.login_rule.-"] == "0"))
            {
                report("550 5.7.1 Policy rejection on the target address", "User blocked");
                return;
            }

            time_t reg_time  = atoi(m_black_box_parser.m_field_map["account_info.reg_date.uid"].c_str());

            if (now < (reg_time + g_time_treshold) )
            {
                report(temp_user_error, "Temporary ban new user");
                return;
            }
        }
        catch(...)
        {
            report(temp_user_error, "Black box return no account_info.reg_date.uid");
            return;
        }

        if ((m_black_box_parser.m_karma_status != 2) && ((m_black_box_parser.m_karma_status != 0) || (m_black_box_parser.m_karma == 85) || (m_black_box_parser.m_karma == 100)))
        {
            if ((m_black_box_parser.m_karma == 85) && (m_black_box_parser.m_karma_status == 0))
            {
                report("250 Ok", "Success");
                return;
            }


            if (m_black_box_parser.m_ban_time > now)
            {
                report(temp_user_error, "Temporary ban user");
                return;
            }
            else
            {
                report("550 5.7.1 Policy rejection on the target address", "User has bad karma");
                return;
            }
        }

        /*      std::cout << "karma:" << m_black_box_parser.m_karma << std::endl;
                std::cout << "karmastatus:" << m_black_box_parser.m_karma_status << std::endl;
                std::cout << "bantime:" << m_black_box_parser.m_ban_time << std::endl;
                std::cout << "uid:" << m_black_box_parser.m_uid << std::endl;

                for(black_box_parser::field_map::iterator it =  m_black_box_parser.m_field_map.begin(); it != m_black_box_parser.m_field_map.end(); it++)
                {
                std::cout << "field: " << it->first << " value: " << it->second << std::endl;
                }*/

        report("250 Ok", "Success");
    }
}

void black_box_client_rcpt::report(const std::string &_response, const std::string &_log, bool success)
{

    if (m_set_rcpt_status)
    {
#if defined(HAVE_PA_ASYNC_H)
        pa::async_profiler::add(pa::passport, m_log_host, "blackbox_session", m_check_rcpt.m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop());
#endif

        if (success)
            g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-BB: bbatt try=%3%, host='%4%', delay=%5%, stat=ok")
                            % m_check_rcpt.m_session_id %  m_envelope->m_id % (m_connect_count-1) % m_log_host % timer::format_time(m_log_delay.mark())));

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-BB: rcpt='%3%', status='%4%', report='%5%'") % m_check_rcpt.m_session_id % m_envelope->m_id % m_check_rcpt.m_rcpt % _log % _response));

        int code = atoi(_response.c_str());

        if (code >= 500)
        {
            m_check_rcpt.m_result = check_rcpt_t::CHK_REJECT;
            m_check_rcpt.m_answer = _response + "\r\n";
        }
        if (code >= 400)
        {
            m_check_rcpt.m_result = check_rcpt_t::CHK_TEMPFAIL;
            m_check_rcpt.m_answer = _response + "\r\n";
        }
        else
        {
            m_check_rcpt.m_result = check_rcpt_t::CHK_ACCEPT;
        }

        m_io_service.post(m_set_rcpt_status);

        m_set_rcpt_status = NULL;
    }
}

void black_box_client_rcpt::stop()
{
    m_io_service.post(m_strand.wrap(bind(&black_box_client_rcpt::do_stop, shared_from_this())));
}

void black_box_client_rcpt::do_stop()
{
    m_http_client->stop();
    m_http_client.reset(); // http_client shares this; this shares http_client, we need to break this circle here
}

#endif // ENABLE_AUTH_BLACKBOX
