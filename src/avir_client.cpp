#include <iostream>
#include <istream>
#include <ostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include "avir_client.h"
#include "log.h"

using namespace y::net;

//--------------------------------------------------------------------------
// error codes:
#define DRWEBD_DEMO_USAGE    -1
#define DRWEBD_IN_FILE       -2
#define DRWEBD_NO_MEMORY     -3
#define DRWEBD_SOCKET_ERR    -4
#define DRWEBD_SWRITE_ERR    -5
#define DRWEBD_SREAD_ERR     -6
#define DRWEBD_TIMEOUT       -7

//--------------------------------------------------------------------------
// Dr. Web daemon exit codes:
#define DERR_READ_ERR            0x0001
#define DERR_WRITE_ERR           0x0002
#define DERR_NOMEMORY            0x0004
#define DERR_CRC_ERROR           0x0008
#define DERR_READSOCKET          0x0010
#define DERR_KNOWN_VIRUS         0x0020
#define DERR_UNKNOWN_VIRUS       0x0040
#define DERR_VIRUS_MODIFICATION  0x0080
#define DERR_FILE_IS_CURED       0x0100
#define DERR_TIMEOUT             0x0200
#define DERR_SYMLINK             0x0400
#define DERR_NO_REGFILE          0x0800
#define DERR_SKIPPED             0x1000
#define DERR_TOO_BIG             0x2000
#define DERR_TOO_COMPRESSED      0x4000
#define DERR_BAD_CALL            0x8000
/* -- copy from http://www.corpit.ru/pipermail/avcheck/2004q2/000974.html */
#define DERR_EVAL_KEY               (1<<16) /*= 0x00010000 */
#define DERR_FILTER_REJECT          (1<<17) /*= 0x00020000 */
#define DERR_ARCHIVE_LEVEL          (1<<18) /*= 0x00040000 */
#define DERR_HAVE_DELETED           (1<<19) /*= 0x00080000 */
#define DERR_IS_CLEAN               (1<<20) /*= 0x00100000 */
#define DERR_LICENSE_ERROR          (1<<21) /*= 0x00200000 */
#define DERR_MASK                   (0x00FFFFFF)
#define DERR_NON_DAEMON_ERROR       (~DERR_MASK)
#define DERR_INFECTED               (DERR_KNOWN_VIRUS | DERR_VIRUS_MODIFICATION)
#define DERR_SUSPICIOUS             (DERR_UNKNOWN_VIRUS)
#define DERR_VIRUS_MASK             (DERR_INFECTED | DERR_SUSPICIOUS)
#define DERR_SKIP_OBJECT            (DERR_SYMLINK | DERR_NO_REGFILE | DERR_SKIPPED | DERR_CRC_ERROR | DERR_TIMEOUT)
#define DERR_ARCHIVE_RESTRICTION    (DERR_TOO_BIG | DERR_TOO_COMPRESSED | DERR_ARCHIVE_LEVEL)
#define DERR_DAEMON_ERROR           (DERR_READ_ERR | DERR_WRITE_ERR | DERR_NOMEMORY | DERR_READSOCKET | DERR_BAD_CALL)


//--------------------------------------------------------------------------
// Dr. Web daemon commands:
#define DRWEBD_SCAN_CMD       0x0001
#define DRWEBD_VERSION_CMD    0x0002
#define DRWEBD_BASEINFO_CMD   0x0003
#define DRWEBD_IDSTRING_CMD   0x0004

// DRWEBD_SCAN_FILE command flags:
#define DRWEBD_RETURN_VIRUSES 0x0001
#define DRWEBD_RETURN_REPORT  0x0002
#define DRWEBD_RETURN_CODES   0x0004
#define DRWEBD_HEURISTIC_ON   0x0008
#define DRWEBD_IS_MAIL        (1<<19)
#define DRWEBD_CURE_FILES     0x0010

using boost::asio::ip::tcp;

avir_client::avir_client(boost::asio::io_service& io_service, switchcfg *_config)
        : m_resolver(io_service),
          m_socket(io_service),
          strand_(io_service),
          m_config(_config),
          m_timer(io_service)
{
}

void avir_client::start(const check_data_t& _data, complete_cb_t _complete_cb, envelope_ptr _envelope)
{
    m_envelope = _envelope;
    m_data = _data;
    m_complete = _complete_cb;

    m_try = 0;
    m_envelope_size = m_envelope->orig_message_size_;

    m_socket.get_io_service().post(
        strand_.wrap(
            boost::bind(&avir_client::restart, shared_from_this()))
        );
}

void avir_client::do_stop()
{
    try
    {
        m_resolver.cancel();
        m_socket.close();
        m_timer.cancel();
    }
    catch(...)
    {
    }
}

void avir_client::stop()
{
    m_socket.get_io_service().post(
        strand_.wrap(
            boost::bind(&avir_client::do_stop, shared_from_this()))
        );
}

void avir_client::restart()
{
    try
    {
        m_socket.close();
        m_resolver.cancel();
    }
    catch(...)
    {
        // skip
    }

    m_timer_value = g_config.m_av_connect_timeout;

    std::ostream request_stream(&m_request);

    int scan_options = 0;
    scan_options |= DRWEBD_RETURN_VIRUSES;
    scan_options |= DRWEBD_RETURN_CODES;
    scan_options |= DRWEBD_IS_MAIL;

    int buffer = htonl(DRWEBD_SCAN_CMD);
    request_stream.write((char*)&buffer, sizeof(buffer));

    buffer = htonl(scan_options);
    request_stream.write((char*)&buffer, sizeof(buffer));

    buffer = 0;
    request_stream.write((char*)&buffer, sizeof(buffer));

    buffer = htonl(m_envelope_size);
    request_stream.write((char*)&buffer, sizeof(buffer));

    server_parameters::remote_point info = (m_try >= g_config.m_av_try ) ? m_config->get_secondary() : m_config->get_primary();

    m_log_host = str(boost::format("%1%:%2%") % info.m_host_name % info.m_port);

    m_log_delay.start();

    restart_timeout();

    m_log_connect = false;
    m_log_check = false;

    try
    {
        boost::asio::ip::tcp::endpoint point(
            boost::asio::ip::address::from_string(info.m_host_name),
            info.m_port);
        m_socket.async_connect(point,
                strand_.wrap(boost::bind(&avir_client::handle_connect,
                                shared_from_this(), boost::asio::placeholders::error,
                                dns::resolver::iterator(), info.m_port)));
    }
    catch (...)
    {
        m_resolver.async_resolve(
            info.m_host_name,
            dns::type_a,
            strand_.wrap(boost::bind(&avir_client::handle_resolve,
                            shared_from_this(),
                            boost::asio::placeholders::error,
                            boost::asio::placeholders::iterator,
                            info.m_port)));
    }


}

void avir_client::handle_resolve(const boost::system::error_code& ec, dns::resolver::iterator it, int port)
{
    if (!ec)
    {
        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), port);

        restart_timeout();

        m_socket.async_connect(point,
                strand_.wrap(boost::bind(&avir_client::handle_connect, shared_from_this(),
                                boost::asio::placeholders::error, ++it, port)
                             ));
        return;
    }

    if (ec != boost::asio::error::operation_aborted)            // cancel after timeout
        fault( std::string("Resolve error: ") + ec.message());
}

void avir_client::handle_connect(const boost::system::error_code& ec, dns::resolver::iterator it, int port)
{
    if (!ec)
    {
        m_timer_value = g_config.m_av_timeout;

        restart_timeout();

        boost::asio::async_write(m_socket, m_request,
                strand_.wrap(boost::bind(&avir_client::handle_write_prolog,
                                shared_from_this(), boost::asio::placeholders::error)));
        return;
    }
    else if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }
    else if (it != dns::resolver::iterator()) // if not last address
    {
        m_socket.close();
        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), port);
        m_socket.async_connect(point,
                strand_.wrap(boost::bind(&avir_client::handle_connect,
                                shared_from_this(), boost::asio::placeholders::error,
                                ++it, port)));
        return;
    }

    fault(std::string("Connect error:") + ec.message());
}

void avir_client::handle_write_prolog(const boost::system::error_code& _err)
{
    if (!_err)
    {
        m_log_connect = true;
        boost::asio::async_write(m_socket, m_envelope->orig_message_,
                boost::asio::transfer_at_least(m_envelope_size),
                strand_.wrap(boost::bind(&avir_client::handle_write_request,
                                shared_from_this(),boost::asio::placeholders::error)));
    }
    else
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            fault(std::string("Protocol error: ") + _err.message());
        }
    }
}

void avir_client::handle_write_request(const boost::system::error_code& _err)
{
    if (!_err)
    {                           // read answer
        boost::asio::async_read(m_socket,
                boost::asio::buffer(m_buffer),
                boost::asio::transfer_at_least(4),
                strand_.wrap(boost::bind(&avir_client::handle_read_status,
                                shared_from_this(), boost::asio::placeholders::error,
                                boost::asio::placeholders::bytes_transferred)));
    }
    else
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            fault(std::string("Protocol error: ") + _err.message());
        }
    }
}

void avir_client::handle_read_status(const boost::system::error_code& _e,  std::size_t _bytes_transferred)
{
    if (_e)
    {
        if (_e == boost::asio::error::operation_aborted)
            return;

        fault(std::string("Connection closed unexpectly: ") + _e.message());

        return;
    }

    if (_bytes_transferred == 0)
    {
        success(false);
    }

    int status = ntohl(m_buffer[0]);

    if ((status & DERR_IS_CLEAN) != 0)
    {
        success(false);
    }
    else if ((status & (DERR_KNOWN_VIRUS | DERR_UNKNOWN_VIRUS)) != 0)
    {
        success(true);
    }
    else
    {
        fault(str(boost::format("Unknown DrWeb status! (%1%)") % status));
    }
}

void avir_client::log_try(const std::string &_status, const std::string &_log)
{
    g_log.msg(MSG_NORMAL,boost::str(boost::format("%1%-%2%-AVIR: ravatt connect=%3%, check=%4%, host='%5%', delay=%6%, size=%7%, status='%8%', msg='%9%'")
                    % m_data.m_session_id
                    % m_envelope->m_id
                    % (m_log_connect ? "ok" : "error")
                    % (m_log_check ? "ok" : "error")
                    % m_log_host
                    % timer::format_time(m_log_delay.mark())
                    % m_envelope->orig_message_size_
                    % _status
                    % _log
                                    ));
}


void avir_client::fault(const std::string &_log)
{

    if (m_complete)
    {
        log_try("error", _log);

        m_try++;

        if (m_try >= g_config.m_av_try * 2)
        {
            m_data.m_result = check::CHK_ACCEPT;

            if (m_complete)
            {
#if defined(HAVE_PA_ASYNC_H)
                pa::async_profiler::add(pa::antivirus, m_log_host, "av_check_fault", m_data.m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop());
#endif
                m_socket.get_io_service().post(m_complete);
                m_complete = NULL;
                m_timer.cancel();
            }

            return;
        }

        m_socket.get_io_service().post(
            strand_.wrap(
                boost::bind(&avir_client::restart, shared_from_this()))
            );
    }
}

void avir_client::success(bool _infected)
{

    if (m_complete)
    {
        m_log_connect = m_log_check = true;

        log_try((_infected ? "infected" : "clean" ), "");

        if (_infected)
        {
            if (g_config.m_action_virus == 0)
            {
                m_data.m_result = check::CHK_DISCARD;
            }
            else
            {
                m_data.m_result = check::CHK_REJECT;

                m_data.m_answer = "554 5.7.1 Message infected by virus; ";
            }
        }
        else
        {
            m_data.m_result = check::CHK_ACCEPT;
        }

#if defined(HAVE_PA_ASYNC_H)
        pa::async_profiler::add(pa::antivirus, m_log_host, "av_check", m_data.m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop());
#endif

        m_socket.get_io_service().post(m_complete);
        m_complete = NULL;
        m_timer.cancel();
    }
}

void avir_client::handle_timer(const boost::system::error_code& _e)
{
    if (!_e)
    {
        fault("Antivirus check timeout");
    }
}

void avir_client::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(strand_.wrap(boost::bind(&avir_client::handle_timer, shared_from_this(), boost::asio::placeholders::error)));
}
