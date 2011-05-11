#include <iostream>
#include <fstream>

#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>

#include "log.h"
#include "smtp_client.h"
#include "uti.h"

using namespace y::net;

smtp_client::smtp_client(boost::asio::io_service &_io_service):
        m_socket(_io_service),
        strand_(_io_service),
        m_resolver(_io_service),
        m_timer(_io_service)
{
}

void smtp_client::start_read_line()
{
    restart_timeout();
    boost::asio::async_read_until(m_socket,
            m_request,
            "\n",
            strand_.wrap(boost::bind(&smtp_client::handle_read_smtp_line, shared_from_this(),
                            boost::asio::placeholders::error)));
}

std::string log_request_helper(const boost::asio::streambuf& buf)
{
    boost::asio::const_buffers_1 b = static_cast<boost::asio::const_buffers_1>(buf.data());
    boost::iterator_range<const char*> ib(buffer_cast<const char*>(b),
            buffer_cast<const char*>(b) + buffer_size(b));
    return string(ib.begin(), ib.end());
}

void log_request(const char* d, size_t sz,
        std::list< std::string >& session_extracts,
        std::list< boost::asio::const_buffer >& session_log,
        time_t session_time)
{
    boost::iterator_range<const char*> ib(d, d+sz);
    session_extracts.push_back(str( boost::format(">> %3% [%1%]:%2%") % sz % ib % (time(0) - session_time)));
    const std::string& s = session_extracts.back();
    session_log.push_back( boost::asio::const_buffer(s.c_str(), s.size()) );
}

void log_request(const std::list< boost::asio::const_buffer >& d, size_t sz,
        std::list< std::string >& session_extracts,
        std::list< boost::asio::const_buffer >& session_log,
        time_t session_time)
{
    session_extracts.push_back(str( boost::format(">> %2% [%1%]:") % sz % (time(0) - session_time)));
    const std::string& s = session_extracts.back();
    session_log.push_back( boost::asio::const_buffer(s.c_str(), s.size()) );
    session_log.insert(session_log.end(), d.begin(), d.end());
}

void smtp_client::handle_read_smtp_line(const boost::system::error_code &_err)
{
    if (!_err)
    {
        std::istream response_stream(&m_request);

        if (process_answer(response_stream))
        {
            boost::asio::async_write(m_socket, m_response,
                    strand_.wrap(boost::bind(&smtp_client::handle_write_request,
                                    shared_from_this(), _1, _2, log_request_helper(m_response))));
        }
    }
}


bool smtp_client::process_answer(std::istream &_stream)
{
    std::ostream answer_stream(&m_response);
    std::string line_buffer;

    while (std::getline(_stream, line_buffer))
    {
        if (_stream.eof() || _stream.fail() || _stream.bad())
        {
            m_line_buffer = line_buffer;
            start_read_line();
            return false;
        }

        if (!m_line_buffer.empty())
        {
            m_line_buffer += line_buffer;
            line_buffer = m_line_buffer;
            m_line_buffer.clear();
        }

        if ((m_proto_state == STATE_HELLO) && (line_buffer.find("PIPELINING") != std::string::npos))
        {
            m_use_pipelining = true;
        }

        if (line_buffer.length() >= 3 && line_buffer[3] == '-')
        {
            continue;
        }

        unsigned int code = 0;

        try
        {
            code = boost::lexical_cast<unsigned int>(line_buffer.substr(0, 3));
        }
        catch (boost::bad_lexical_cast)
        {
            fault( "Invalid proto state", line_buffer);
            return false;
        }

        switch (m_proto_state)
        {
            case STATE_ERROR:
                break;

            case STATE_START:

                if (code != 220)
                {
                    fault( "Invalid greeting", line_buffer);
                    return false;
                }
                else
                {

                    m_timer_value = g_config.m_relay_cmd_timeout;

                    if (m_lmtp)
                    {
                        answer_stream << "LHLO " << boost::asio::ip::host_name() << "\r\n";
                    }
                    else
                    {
                        answer_stream << "EHLO " << boost::asio::ip::host_name() << "\r\n";
                    }

                    m_proto_state = STATE_HELLO;
                }
                break;

            case STATE_HELLO:

                if (code != 250)
                {
                    fault( "Invalid answer on EHLO command", line_buffer);
                    return false;
                }
                else
                {
                    std::string next_command;

                    if (m_use_pipelining)
                    {
                        next_command.append("MAIL FROM: <" + m_envelope->m_sender + ">\r\n");

                        for(m_current_rcpt = m_envelope->m_rcpt_list.begin();
                            m_current_rcpt != m_envelope->m_rcpt_list.end();
                            m_current_rcpt++)
                        {
                            next_command.append("RCPT TO: <" + m_current_rcpt->m_name +">\r\n");
                        }

                        next_command.append("DATA\r\n");
                    }
                    else
                    {
                        next_command.assign("MAIL FROM: <" + m_envelope->m_sender + ">\r\n");
                    }

                    g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-SEND-%3%: from=<%4%>") % m_data.m_session_id % m_envelope->m_id % m_proto_name % m_envelope->m_sender));

                    m_proto_state = STATE_AFTER_MAIL;

                    answer_stream << next_command;
                }
                break;

            case STATE_AFTER_MAIL:
                if (code != 250)
                {
                    fault( "Invalid answer on MAIL command", line_buffer);
                    return false;
                }
                else
                {
                    m_proto_state = STATE_AFTER_RCPT;
                    m_current_rcpt = m_envelope->m_rcpt_list.begin();

                    if (m_current_rcpt == m_envelope->m_rcpt_list.end())
                    {
                        g_log.msg(MSG_NORMAL, "Bad recipient list");
                        fault( "Inavalid", line_buffer);
                    }

                    if (!m_use_pipelining)
                        answer_stream << "RCPT TO: <" << m_current_rcpt->m_name  << ">\r\n";
                }
                break;

            case STATE_AFTER_RCPT:

                if (code != 250)
                {
                    fault( "Invalid answer on RCPT command", line_buffer);
                    return false;
                }
                else
                {
                    m_current_rcpt++;

                    if ( m_current_rcpt == m_envelope->m_rcpt_list.end() )
                    {
                        m_proto_state = STATE_AFTER_DATA;

                        if (!m_use_pipelining)
                            answer_stream << "DATA\r\n";
                    }
                    else
                    {
                        if (!m_use_pipelining)
                            answer_stream << "RCPT TO: <" << m_current_rcpt->m_name  << ">\r\n";
                    }
                }
                break;

            case STATE_AFTER_DATA:

                if (code != 354)
                {
                    fault("Invalid answer on DATA command", line_buffer);
                    return false;
                }
                else
                {

                    if (m_lmtp)
                    {
                        m_current_rcpt = m_envelope->m_rcpt_list.begin();
                    }

                    m_timer_value = g_config.m_relay_data_timeout;

                    restart_timeout();

                    m_proto_state = STATE_AFTER_DOT;

                    boost::asio::async_write(m_socket, m_envelope->altered_message_,
                            strand_.wrap(boost::bind(&smtp_client::handle_write_data_request,
                                            shared_from_this(), _1, _2)));

                    return false;
                }
                break;

            case STATE_AFTER_DOT:

                m_timer_value = g_config.m_relay_cmd_timeout;

                if (m_lmtp)
                {
                    m_current_rcpt->m_delivery_status = envelope::smtp_code_decode(code);
                    m_current_rcpt->m_remote_answer = line_buffer;
                    m_current_rcpt++;

                    if (m_current_rcpt == m_envelope->m_rcpt_list.end())
                    {
                        success();

                        return false;

                        answer_stream << "QUIT\r\n";
                        m_proto_state = STATE_AFTER_QUIT;
                    }
                }
                else
                {
                    for(m_current_rcpt = m_envelope->m_rcpt_list.begin(); m_current_rcpt != m_envelope->m_rcpt_list.end(); m_current_rcpt++)
                    {
                        m_current_rcpt->m_delivery_status = envelope::smtp_code_decode(code);
                        m_current_rcpt->m_remote_answer = line_buffer;
                    }

                    success();

                    return false;

                    answer_stream << "QUIT\r\n";
                    m_proto_state = STATE_AFTER_QUIT;
                }

                break;

            case STATE_AFTER_QUIT:
                try
                {
                    m_socket.close();
                }
                catch(...)
                {
                    //skip
                }
                return false;

                break;


        }

        line_buffer.clear();

    }

    return true;
}

void smtp_client::start(const check_data_t& _data,
        complete_cb_t _complete,
        envelope_ptr _envelope,
        const server_parameters::remote_point &_remote,
        const char *_proto_name )
{
#if defined(HAVE_PA_ASYNC_H)
    m_pa_timer.start();
#endif

    m_data = _data;
    m_complete = _complete;
    m_envelope = _envelope;

    m_envelope->cleanup_answers();

    m_lmtp = _remote.m_proto == "lmtp";
    m_proto_name = _proto_name;

    m_timer_value = g_config.m_relay_connect_timeout;

    m_proto_state = STATE_START;

    m_relay_name = _remote.m_host_name;
    m_relay_port = _remote.m_port;

    m_use_pipelining = false;

    restart_timeout();

    try
    {
        m_endpoint.address(boost::asio::ip::address::from_string(m_relay_name));
        m_endpoint.port(_remote.m_port);

        m_relay_ip = m_relay_name;

        m_socket.async_connect(m_endpoint,
                strand_.wrap(boost::bind(&smtp_client::handle_simple_connect,
                                shared_from_this(), boost::asio::placeholders::error)));
    }
    catch(...)
    {

        //        g_log.msg(MSG_NORMAL, str( boost::format("%1%-%2%-SEND-%3%S connect to: %4%:%5%") % m_data->m_session_id % m_envelope->m_id % m_proto_name % m_relay_name % m_relay_port));

        m_resolver.async_resolve(
            m_relay_name,
            dns::type_a,
            strand_.wrap(boost::bind(&smtp_client::handle_resolve,
                            shared_from_this(),
                            boost::asio::placeholders::error,
                            boost::asio::placeholders::iterator)));
    }

}

void smtp_client::handle_resolve(const boost::system::error_code& ec, dns::resolver::iterator it)
{
    if (!ec)
    {
        restart_timeout();

        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), m_relay_port);

        m_relay_ip = point.address().to_string();

        g_log.msg(MSG_NORMAL, str( boost::format("%1%-%2%-SEND-%3% connect: ip=[%4%]") % m_data.m_session_id % m_envelope->m_id % m_proto_name % m_relay_ip));

        m_socket.async_connect(point,
                strand_.wrap(boost::bind(&smtp_client::handle_connect,
                                shared_from_this(),
                                boost::asio::placeholders::error, ++it)));
        return;
    }

    if (ec != boost::asio::error::operation_aborted)            // cancel after timeout
        fault( std::string("Resolve error: ") + ec.message(), "");
}

void smtp_client::handle_simple_connect(const boost::system::error_code& error)
{
    if (!error)
    {
        m_proto_state = STATE_START;

        m_timer_value = g_config.m_relay_connect_timeout;

        start_read_line();
    }
    else
    {
        if (error != boost::asio::error::operation_aborted)
        {
            fault("Can't connect to host: " + error.message(), "");
        }
    }
}

void smtp_client::handle_connect(const boost::system::error_code& ec, dns::resolver::iterator it)
{
    if (!ec)
    {
        m_proto_state = STATE_START;

        m_timer_value = g_config.m_relay_connect_timeout;

        start_read_line();
        return;
    }
    else if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }
    else if (it != dns::resolver::iterator()) // if not last address
    {
        m_socket.close();

        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), m_relay_port);

        m_relay_ip = point.address().to_string();

        g_log.msg(MSG_NORMAL, str( boost::format("%1%-%2%-SEND-%3% connect ip =%4%") % m_data.m_session_id % m_envelope->m_id % m_proto_name % m_relay_ip));

        m_socket.async_connect(point,
                strand_.wrap(boost::bind(&smtp_client::handle_connect,
                                shared_from_this(),
                                boost::asio::placeholders::error, ++it)));
        return;
    }

    fault("Can't connect to host: " + ec.message(), "");
}

void smtp_client::handle_write_data_request(const boost::system::error_code& _err, size_t sz)
{
    if (_err)
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            fault("Write error: " + _err.message(), "");
        }
    }
    else
    {
        std::ostream answer_stream(&m_response);

        answer_stream << ".\r\n";

        boost::asio::async_write(m_socket, m_response,
                strand_.wrap(boost::bind(&smtp_client::handle_write_request, shared_from_this(),
                                _1, _2, log_request_helper(m_response))));
    }
}


void smtp_client::handle_write_request(const boost::system::error_code& _err, size_t sz, const std::string& s)
{
    if (_err)
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            fault("Write error: " + _err.message(), "");
        }
    }
    else
    {
        start_read_line();
    }
}

check::chk_status smtp_client::report_rcpt(bool _success, const std::string &_log, const std::string &_remote)
{
    bool accept = true;

    for(envelope::rcpt_list_t::iterator it = m_envelope->m_rcpt_list.begin(); it != m_envelope->m_rcpt_list.end(); it++)
    {
        std::string remote;

        if (!it->m_remote_answer.empty())
        {
            remote = cleanup_str(it->m_remote_answer);
        }
        else if (!_remote.empty())
        {
            remote = cleanup_str(_remote);
        }
        else
        {
            remote = _log;
        }

        bool rcpt_success = (it->m_delivery_status == check::CHK_ACCEPT);

        std::string rcpt_success_str = rcpt_success ? "sent" : "fault";

        accept &= rcpt_success;

        g_log.msg(MSG_NORMAL, str( boost::format("%1%-%2%-SEND-%3%: to=<%4%>, relay=%5%[%6%]:%7%, delay=%8%, status=%9% (%10%)")
                        % m_data.m_session_id % m_envelope->m_id % m_proto_name
                        % it->m_name
                        % m_relay_name % m_relay_ip % m_relay_port
                        % m_envelope->m_timer.mark()
                        % rcpt_success_str % remote ));
    }

#if defined(HAVE_PA_ASYNC_H)
    pa::async_profiler::add(pa::smtp_out, m_relay_name + "[" + m_relay_ip+ "]", m_lmtp ? "lmtp_out_session" : "smtp_out_session", m_data.m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop());
#endif

    return accept ? check::CHK_ACCEPT : check::CHK_TEMPFAIL;
}


void smtp_client::fault(const std::string &_log, const std::string &_remote)
{
    if (m_complete)
    {
        m_proto_state = STATE_ERROR;

        m_data.m_result = report_rcpt(false, _log, _remote);

        m_timer.cancel();
        m_resolver.cancel();

        try {
            m_socket.close();
        } catch (...) {}

        m_socket.get_io_service().post(m_complete);
        m_complete = NULL;
    }
}

void smtp_client::success()
{
    if (m_complete)
    {
        m_data.m_result = report_rcpt(true, "Success delivery", "");

        m_timer.cancel();
        m_resolver.cancel();

        try {
            m_socket.close();
        } catch (...) {}

        m_socket.get_io_service().post(m_complete);
        m_complete = NULL;
    }
}

void smtp_client::do_stop()
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

void smtp_client::stop()
{
    m_socket.get_io_service().post(
        strand_.wrap(
            boost::bind(&smtp_client::do_stop, shared_from_this()))
        );
}

void smtp_client::handle_timer(const boost::system::error_code& _e)
{
    if (!_e)
    {
        const char* state = "";
        switch (m_proto_state)
        {
            case STATE_START:
                state = "STATE_START";
                break;
            case STATE_HELLO:
                state = "STATE_HELLO";
                break;
            case STATE_AFTER_MAIL:
                state = "STATE_AFTER_MAIL";
                break;
            case STATE_AFTER_RCPT:
                state = "STATE_AFTER_RCPT";
                break;
            case STATE_AFTER_DATA:
                state = "STATE_AFTER_DATA";
                break;
            case STATE_AFTER_DOT:
                state = "STATE_AFTER_DOT";
                break;
            case STATE_AFTER_QUIT:
                state = "STATE_AFTER_QUIT";
                break;
            case STATE_ERROR:
                state = "STATE_ERROR";
                break;
        }

        fault( string("SMTP/LMTP client connection timeout: ") + state, "");
    }
}

void smtp_client::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(strand_.wrap(boost::bind(&smtp_client::handle_timer, shared_from_this(), boost::asio::placeholders::error)));
}
