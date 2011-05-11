#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <iostream>
#include <boost/format.hpp>
#include <boost/tokenizer.hpp>

#include "log.h"
#include "so_client.h"
#include "options.h"
#include "uti.h"

const unsigned int K64 = 64*1024;

using namespace y::net;


const char *spam_flag_chunk = "X-Spam-Flag: DLVR";

const char *so_daemon_chunk = "SODAEMON ";
const int so_daemon_chunk_len = strlen(so_daemon_chunk);

struct spam_status
{

    static so_client::spam_status_t parse_so_answer(const std::string &_buffer, envelope_ptr _envelope)
    {
        so_client::spam_status_t ret_code = so_client::SO_HAM;

        std::stringstream ss(_buffer);

        bool parse_spam_str = false;

        while (ss.good())
        {
            std::string line;

            getline(ss, line);

            if (parse_spam_str)
            {
        	if (line == spam_flag_chunk)
        	{
        	    ret_code = so_client::SO_DELIVERY;
        	}
            }
            else if (strncmp (line.c_str(), so_daemon_chunk, so_daemon_chunk_len) == 0)
            {
                int answer_size = 0;

                if (sscanf (line.c_str(), "%*s %d", &answer_size) == 1)
                {
                    if (answer_size == 0) // empty reply, just deliver
                    {
                        return so_client::SO_SKIP;
                    }
                }
            }
            else if (strncmp (line.c_str(), "REJECT ", 7) == 0)
            {
                int rej = 0;

                if (sscanf (line.c_str(), "%*s %d", &rej) == 1)
                {
                    ret_code = ((rej == 1) || (rej == 2)) ? so_client::SO_MALICIOUS : ret_code ;  //

                    if (ret_code == so_client::SO_MALICIOUS)
                    {
                        break;
                    }
                }
            }
            else if (strncmp (line.c_str(), "SPAM ", 5) == 0)
            {

                typedef boost::tokenizer<boost::char_separator<char> > tokenizer;

                boost::char_separator<char> sep(" ,");
                tokenizer tokens(line, sep);

                tokenizer::iterator tok_iter = tokens.begin();

                if (tok_iter == tokens.end())           //      error
                {
                    ret_code = so_client::SO_FAULT;
                    break;
                }

                tok_iter ++;

                so_client::spam_status_t inv_ret_code = so_client::SO_SPAM;

                if (tok_iter == tokens.end())
                {
                    ret_code = so_client::SO_FAULT;             //error
                    break;
                }
                else
                {                                               // ok
                    ret_code = (*tok_iter == "0") ? so_client::SO_HAM : so_client::SO_SPAM;
                    inv_ret_code = (*tok_iter == "0") ? so_client::SO_SPAM : so_client::SO_HAM;
                }

                for (tok_iter++; tok_iter != tokens.end(); tok_iter++)
                {
                    _envelope->set_personal_spam_status(atoll(tok_iter->c_str()), inv_ret_code);
                }

            }
            else if (strncmp (line.c_str(), "SPAMSTR ", 8) == 0)
            {
        	parse_spam_str = true;
            }
        }

        return ret_code;
    };

    static const char *explain_so_internal_code(const so_client::spam_status_t _code)
    {
        switch (_code)
        {
            case so_client::SO_HAM:
                return "(1) ham";

            case so_client::SO_SPAM:
                return "(4) spam";

            case so_client::SO_DELIVERY:
                return "(2) dlv";


            case so_client::SO_MALICIOUS:
                return "(256) malicious spam";

            case so_client::SO_FAULT:
                return "(-1) error";

            default:
                return "(0) skip";
        }

    }

    static bool get_suid_status(envelope_ptr _envelope, std::string &_result)
    {

        std::string buffer;
        unsigned int cnt = 0;

        for(envelope::rcpt_list_t::iterator current_rcpt = _envelope->m_rcpt_list.begin(); current_rcpt != _envelope->m_rcpt_list.end(); current_rcpt++)
        {
            if (current_rcpt->m_spam_status > 0)
            {
                if (cnt == 0)
                {
                    buffer += str(boost::format("%1% %2%") % current_rcpt->m_spam_status % current_rcpt->m_suid);
                }
                else
                {
                    buffer += str(boost::format(",%1% %2%") % current_rcpt->m_spam_status % current_rcpt->m_suid);
                }

                cnt++;
            }
        }

        if (cnt > 0)
        {
            _result = "X-Yandex-Suid-Status: " + buffer + "\r\n";
            return true;
        }

        return false;
    }

    static std::string get_headers(const so_client::spam_status_t _code)
    {
        std::string field = "X-Yandex-Spam: " + boost::lexical_cast<std::string>(_code) + "\r\n";

        return field;
    }
};


so_client::so_client(boost::asio::io_service& _io_service, switchcfg *_so_config)
        :  m_socket(_io_service),
           strand_(_io_service),
           m_resolver(_io_service),
           m_timer(_io_service),
           m_config(_so_config)
{
}

void so_client::start_read_line()
{
    restart_timeout();

    boost::asio::async_read_until(m_socket,
            m_request,
            "\0",
            strand_.wrap(boost::bind(&so_client::handle_read_so_line, shared_from_this(),
                            boost::asio::placeholders::error)));

}

void so_client::write_extra_headers()
{
    if (extra_headers_.empty())
    {
        handle_write_extra_headers(boost::system::error_code());
    }
    else
    {
        boost::asio::async_write(m_socket, boost::asio::buffer(extra_headers_),
                strand_.wrap(boost::bind(&so_client::handle_write_extra_headers, shared_from_this(),boost::asio::placeholders::error)));
    }
}

void so_client::handle_write_extra_headers(const boost::system::error_code& ec)
{
    if (!ec)
    {
        unsigned int send_size = std::min<unsigned int>(K64, m_envelope_size - extra_headers_.size());
        boost::asio::async_write(m_socket, m_envelope->orig_message_,
                boost::asio::transfer_at_least(send_size),
                strand_.wrap(boost::bind(&so_client::handle_write_request, shared_from_this(),boost::asio::placeholders::error)));
    }
    else if (ec != boost::asio::error::operation_aborted)
    {
        fault("Write error: " + ec.message());
    }
}

void so_client::handle_read_so_line(const boost::system::error_code& _err)
{
    if (!_err)
    {
        std::istream response_stream(&m_request);

        try
        {

            if (process_answer(response_stream))
            {

                if  (m_proto_state == STATE_AFTER_DOT)
                {
                    write_extra_headers();

                }
                else
                {

                    boost::asio::async_write(m_socket, m_response,
                            strand_.wrap(boost::bind(&so_client::handle_write_request, shared_from_this(),
                                            boost::asio::placeholders::error)));
                }
            }
        }
        catch(...)
        {
            fault("Invalid answer on connect");
        }

    }
}

bool so_client::process_answer(std::istream &_stream)
{
    std::ostream answer_stream(&m_response);

    std::string header;
    std::string line_buffer;

    while (std::getline(_stream, header))
    {
        std::string::size_type pos = header.find_last_not_of('\0');

        std::string striped(header);

        if (pos != std::string::npos)
        {
            striped = header.substr(0, pos + 1);
        }

        if (header.substr(0,2) == "OK")
        {
            line_buffer.append(striped);
        }
        else
        {
            line_buffer.append(header + "\n");
        }
    }

    switch (m_proto_state)
    {

        case STATE_START:
        case STATE_ERROR:

            fault("Invalid proto state");
            return false;

            break;

        case STATE_AFTER_CONNECT:

            if (line_buffer == "OK REJECT")
            {
                success(so_client::SO_MALICIOUS);
                return false;
            }
            else if (line_buffer == "OK ACCEPT")
            {
                success(so_client::SO_SKIP);
                return false;
            }
            else if (line_buffer == "OK")
            {
                answer_stream << "HELO " << m_data.m_helo_host;
                //<< "\n";
                m_proto_state = STATE_AFTER_HELO;
            }
            else
            {
                fault("Invalid answer on connect");
                return false;
            }
            break;

        case STATE_AFTER_HELO:

            if (line_buffer == "OK")
            {
                answer_stream << "MAILFROM " <<  m_envelope->m_sender << " SIZE="  << m_envelope_size ;
                //              << "\n";

                m_proto_state = STATE_AFTER_MAILFROM;
            }
            else
            {
                fault("Invalid answer on HELO command");
                return false;
            }
            break;

        case STATE_AFTER_MAILFROM:

            if (line_buffer == "OK")
            {
                m_proto_state = STATE_AFTER_RCPTTO;

                m_current_rcpt = m_envelope->m_rcpt_list.begin();

                if (m_current_rcpt == m_envelope->m_rcpt_list.end())
                {
                    fault("No valid recipients");
                    return false;
                }
                else
                {
                    answer_stream << "RCPTTO " <<  m_current_rcpt->m_name;

                    if (m_current_rcpt->m_suid != 0)
                    {
                        answer_stream << " ID=" << m_current_rcpt->m_suid;
                    }

                    //              answer_stream << "\n";
                }
            }
            else
            {
                fault("Invalid answer on MAILFROM command");
                return false;
            }
            break;

        case STATE_AFTER_RCPTTO:

            if (line_buffer != "OK")
            {
                fault("Invalid answer on RCPTTO command");
                return false;
            }
            else
            {
                m_current_rcpt++;

                if ( m_current_rcpt == m_envelope->m_rcpt_list.end() )
                {
                    unsigned int send_size = std::min(K64, m_envelope_size);

                    answer_stream << "DATA SIZE=" << send_size  << "\n";

                    m_proto_state = STATE_AFTER_DATA;
                }
                else
                {
                    answer_stream << "RCPTTO " <<  m_current_rcpt->m_name;

                    if (m_current_rcpt->m_suid != 0)
                    {
                        answer_stream << " ID=" << m_current_rcpt->m_suid;
                    }

                    //              answer_stream << "\n";
                }
            }
            break;

        case STATE_AFTER_DATA:
            if (line_buffer != "OK")
            {
                fault("Invalid answer on DATA command");
                return false;
            }
            else
            {
                m_proto_state = STATE_AFTER_DOT;
            }
            break;

        case STATE_AFTER_DOT:
            {
                so_client::spam_status_t spam_status =  spam_status::parse_so_answer(line_buffer, m_envelope);

                success(spam_status);

                return false;
            }
            break;

    }

    return true;
}

void so_client::start(const check_data_t& _data, complete_cb_t _complete, envelope_ptr _envelope,
        std::string smtp_from, boost::optional<std::string> spf_result, boost::optional<std::string> spf_expl)
{
#if defined(HAVE_PA_ASYNC_H)
    m_pa_timer.start();
#endif

    m_data = _data;
    m_complete = _complete;
    m_envelope = _envelope;

    // compose extra headers for SO only

    extra_headers_ = str(boost::format("X-Yandex-QueueID: %1%-%2%\r\n") % m_data.m_session_id % m_envelope->m_id);

    #ifdef ENABLE_AUTH_BLACKBOX
    if (m_envelope->auth_mailfrom_)
    {
	extra_headers_ += str(boost::format("X-Yandex-KarmaStatus: %1%\r\nX-Yandex-Karma: %2%\r\nX-BornDate: %3%\r\n") % m_envelope->karma_status_ % m_envelope->karma_ % m_envelope->time_stamp_);
    }
    else
    {
	 if (spf_result && spf_expl)
	{
    	    extra_headers_ += str(boost::format("Received-SPF: %1% (%2%) envelope-from=%3%\r\n")
                % spf_result.get() % spf_expl.get() % smtp_from);
	}
    }
    #else
    if (spf_result && spf_expl)
    {
        extra_headers_ += str(boost::format("Received-SPF: %1% (%2%) envelope-from=%3%\r\n")
            % spf_result.get() % spf_expl.get() % smtp_from);
    }
    #endif

    if (g_config.add_xyg_after_greylisting_ && _envelope->m_spam)
    {
        for (envelope::rcpt_list_t::iterator it = m_envelope->m_rcpt_list.begin();
             it != m_envelope->m_rcpt_list.end();
             ++it)
        {
            const greylisting_client::info_t& i = it->gr_check_->info();
            extra_headers_ += str(boost::format("X-Yandex-Greylisting: %1% %2% %3% %4%\r\n")
                    % i.suid % i.age % i.n % i.m);
        }
    }

    m_timer_value = g_config.m_so_connect_timeout;

    m_proto_state = STATE_START;

    m_envelope_size = m_envelope->orig_message_size_ + extra_headers_.size();

    m_so_try = 0;
    m_so_connect_try = 0;

    m_log_delay.start();

    m_socket.get_io_service().post(
        strand_.wrap(
            boost::bind(&so_client::restart, shared_from_this()))
        );
}

void so_client::restart()
{
    try
    {
        m_resolver.cancel();
        m_socket.close();
    }
    catch(...)
    {
        //skip
    }

    server_parameters::remote_point info = (m_so_try >= g_config.m_so_try) ? m_config->get_secondary() : m_config->get_primary();

    m_log_host = str(boost::format("%1%:%2%") % info.m_host_name % info.m_port);

    restart_timeout();

    try
    {
        m_endpoint.address(boost::asio::ip::address::from_string(info.m_host_name));
        m_endpoint.port(info.m_port);

        m_socket.async_connect(m_endpoint,
                strand_.wrap(boost::bind(&so_client::handle_simple_connect,
                                shared_from_this(), boost::asio::placeholders::error)));
    }
    catch(...)
    {
        m_resolver.async_resolve(info.m_host_name,
                dns::type_a,
                strand_.wrap(boost::bind(&so_client::handle_resolve,
                                shared_from_this(),
                                boost::asio::placeholders::error,
                                boost::asio::placeholders::iterator,
                                info.m_port)));
    }

}

void so_client::handle_resolve(const boost::system::error_code& ec, dns::resolver::iterator it, int port)
{
    if (!ec)
    {
        restart_timeout();

        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), port);
        m_socket.async_connect(point,
                strand_.wrap(boost::bind(&so_client::handle_connect,
                                shared_from_this(), boost::asio::placeholders::error,
                                ++it, port)));
        return;
    }

    if (ec != boost::asio::error::operation_aborted)            // cancel after timeout
        fault(std::string("Resolve error: ") + ec.message());
}

void so_client::handle_simple_connect(const boost::system::error_code& error)
{
    if (!error)
    {
        m_proto_state = STATE_AFTER_CONNECT;

        m_timer_value = g_config.m_so_timeout;

        std::ostream response_stream(&m_response);

        response_stream << "CONNECT " << m_data.m_remote_host << " [" << m_data.m_remote_ip << "]";

        boost::asio::async_write(m_socket, m_response,
                strand_.wrap(boost::bind(&so_client::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));

        //      start_read_line();
    }
    else
    {
        if (error != boost::asio::error::operation_aborted)
        {
            fault("Can't connect to host: " + error.message());
        }
    }
}



void so_client::handle_connect(const boost::system::error_code& ec, dns::resolver::iterator it, int port)
{
    if (!ec)
    {
        m_proto_state = STATE_AFTER_CONNECT;

        m_timer_value = g_config.m_so_timeout;

        std::ostream response_stream(&m_response);

        response_stream << "CONNECT " << m_data.m_remote_host << " [" << m_data.m_remote_ip << "]";

        boost::asio::async_write(m_socket, m_response,
                strand_.wrap(boost::bind(&so_client::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));

        //      start_read_line();
        return;
    }
    else if (ec == boost::asio::error::operation_aborted)                       // if cancel active
    {
        return;
    }
    else if (it != dns::resolver::iterator()) // if not last address
    {
        m_so_connect_try++;

        try {
            m_socket.close();
        } catch (...) {}

        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), port);

        m_socket.async_connect(point,
                strand_.wrap(boost::bind(&so_client::handle_connect,
                                shared_from_this(),
                                boost::asio::placeholders::error,
                                ++it, port)));
        return;
    }

    fault("Can't connect to host: " + ec.message());
}

void so_client::handle_write_request(const boost::system::error_code& _err)
{
    if (_err)
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            fault("Write error: " + _err.message());
        }
    }
    else
    {
        start_read_line();
    }
}

void so_client::log_finish(so_client::spam_status_t _code)
{
    g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-SOCHECK: remote so_check from=%3%, ip=%4%, status=\"%5%\"")
                    % m_data.m_session_id
                    % m_envelope->m_id
                    % m_envelope->m_sender
                    % m_data.m_remote_ip
                    % spam_status::explain_so_internal_code(_code)
                              ));
}

void so_client::fault(const std::string &_log)
{
    m_proto_state = STATE_ERROR;

    if (m_complete)
    {
#if defined(HAVE_PA_ASYNC_H)
        pa::async_profiler::add(pa::spam, m_log_host, "spam_check_fault", m_data.m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop());
#endif

        m_so_try ++;

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-SOCHECK: rsoatt err_connect=%3%, err_check=%4%, host='%5%', delay=%6%")
                        % m_data.m_session_id %  m_envelope->m_id % m_so_connect_try % m_so_try % m_log_host % timer::format_time(m_log_delay.mark())
                                  )
                  );


        if (m_so_try >= g_config.m_so_try * 2)
        {
            m_data.m_result = check::CHK_TEMPFAIL;

            m_data.m_answer = temp_error;

            m_socket.get_io_service().post(m_complete);

            m_complete = NULL;
            m_timer.cancel();

            log_finish(SO_FAULT);

            return;
        }

        m_socket.get_io_service().post(
            strand_.wrap(
                boost::bind(&so_client::restart, shared_from_this()))
            );
    }

}

void so_client::stop()
{
    m_socket.get_io_service().post(
        strand_.wrap(
            boost::bind(&so_client::do_stop, shared_from_this()))
        );
}

void so_client::do_stop()
{
    try
    {
        m_socket.close();
        m_resolver.cancel();
        m_timer.cancel();
    }
    catch(...)
    {
    }
}

void so_client::success(so_client::spam_status_t _status)
{

    if (m_complete)
    {
#if defined(HAVE_PA_ASYNC_H)
        pa::async_profiler::add(pa::spam, m_log_host, "spam_check", m_data.m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop());
#endif

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-SOCHECK: rsoatt err_connect=%3%, err_check=%4%, host='%5%', delay=%6%")
                        % m_data.m_session_id %  m_envelope->m_id % m_so_connect_try % m_so_try % m_log_host % timer::format_time(m_log_delay.mark())
                                  )
                  );

        log_finish(_status);

        if (_status == SO_MALICIOUS)
        {
            m_data.m_result = check::CHK_REJECT;
            m_data.m_answer = "554 5.7.1 Message rejected under suspicion of SPAM";
        }
        else
        {
            m_envelope->m_spam = (_status == so_client::SO_SPAM);
            append(spam_status::get_headers(_status), m_envelope->added_headers_);

            std::string suid_buffer;

            if (spam_status::get_suid_status(m_envelope, suid_buffer))
            {
                append(suid_buffer, m_envelope->added_headers_);
            }

        }

        m_socket.get_io_service().post(m_complete);

        m_timer.cancel();
        m_complete = NULL;
    }
}

void so_client::handle_timer(const boost::system::error_code& _e)
{
    if (!_e)
    {
        fault( "Connection timeout");
    }
}

void so_client::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(strand_.wrap(boost::bind(&so_client::handle_timer, shared_from_this(), boost::asio::placeholders::error)));
}
