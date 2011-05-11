#include <config.h>

#ifdef ENABLE_AUTH_BLACKBOX

#include <vector>
#include <boost/bind.hpp>
#include <sstream>
#include <iostream>
#include <fstream>
#include <boost/type_traits.hpp>
#include <boost/format.hpp>
#include <algorithm>

#include "smtp_connection.h"
#include "smtp_connection_manager.h"
#include "log.h"
#include "options.h"
#include "uti.h"
#include "ip_options.h"

const char *auth_error = "535 5.7.8 Error: authentication failed:%1%\r\n";

bool smtp_connection::continue_smtp_auth ( const std::string& _cmd, std::ostream &_response )
{
    m_proto_state = STATE_HELLO;

    std::string response;
    black_box_client_auth::auth_info_t info;

    switch (auth_.next(_cmd, response))
    {
        case auth::AUTH_OK:
            _response << "235 2.7.0 Authentication successful";         // Inpossible case

            break;

        case auth::AUTH_DONE:                                           // got all params start BB Auth

            auth_.get_session_params(info.login_, info.password_, info.ip_, info.method_);

            info.session_id_ = m_session_id;

            m_proto_state = STATE_CHECK_AUTH;

            start_passport_auth(info);

            break;

        case auth::AUTH_MORE:

            m_proto_state = STATE_AUTH_MORE;

            _response << response;

            break;

        case auth::AUTH_FORM:
            _response << str(boost::format(auth_error) % "Invalid format.");

            break;
    }

    return true;
}

bool smtp_connection::smtp_auth ( const std::string& _cmd, std::ostream &_response )
{
    if (m_proto_state == STATE_START)
    {
        _response << "503 5.5.1 Error: send HELO/EHLO first\r\n";
        return true;
    }

    if (authenticated_)
    {
        _response << "503 5.5.1 Error: already authenticated\r\n";
        return true;
    }

    std::string::size_type pos = _cmd.find( ' ' );

    std::string command;
    std::string param;

    if ( pos != std::string::npos )     // Split line into command and argument parts
    {
        command = _cmd.substr( 0, pos );
        param = _cmd.substr( pos + 1 );
    }
    else
    {
        command = _cmd;
    }

    std::string response;

    black_box_client_auth::auth_info_t info;

    switch (auth_.first(command, param, response))
    {
        case auth::AUTH_OK:
            _response << "235 2.7.0 Authentication successful";         // Inpossible case

            break;

        case auth::AUTH_DONE:                                           // got all params start BB Auth

            auth_.get_session_params(info.login_, info.password_, info.ip_, info.method_);

            info.session_id_ = m_session_id;

            m_proto_state = STATE_CHECK_AUTH;

            start_passport_auth(info);

            break;

        case auth::AUTH_MORE:

            m_proto_state = STATE_AUTH_MORE;

            _response << response;

            break;

        case auth::AUTH_FORM:
            _response << str(boost::format(auth_error) % "Invalid format.");

            break;
    }

    return true;
}

void smtp_connection::start_passport_auth(const black_box_client_auth::auth_info_t &_info)
{
    if (m_bb_check_auth)
        m_bb_check_auth->stop();

    m_bb_check_auth.reset( new black_box_client_auth(io_service_, &g_bb_switch) );
    m_bb_check_auth->start( _info, strand_.wrap(bind(&smtp_connection::handle_bb_auth_result, shared_from_this(), _1, _2)) );
}

void smtp_connection::handle_bb_auth_result_helper(check::chk_status _status, unsigned long long _suid)
{
    m_proto_state = STATE_HELLO;
    std::ostream response_stream(&m_response);

    switch (_status)
    {
        case check::CHK_ACCEPT:
            authenticated_ = true;
            response_stream << "235 2.7.0 Authentication successful.\r\n";

            m_suid = _suid;

            break;

        case check::CHK_DISCARD:
        case check::CHK_REJECT:
            response_stream << "535 5.7.8 Error: authentication failed: Invalid user or password!\r\n";
            break;

        case check::CHK_TEMPFAIL:
            response_stream << "454 4.3.0 Try again later\r\n";
            break;
    }

    if (ssl_state_ == ssl_active)
    {
        boost::asio::async_write(m_ssl_socket, m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));

    }
    else
    {
        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    }
}


void smtp_connection::handle_bb_auth_result(check::chk_status _check, unsigned long long _suid)
{
    if (!m_bb_check_auth)
        return;

    if (m_bb_check_auth)
        m_bb_check_auth->stop();

    m_bb_check_auth.reset();

    handle_bb_auth_result_helper(_check, _suid);
}

#endif // ENABLE_AUTH_BLACKBOX
