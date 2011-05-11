#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <algorithm>

#include <boost/bind.hpp>
#include <boost/type_traits.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>

#include "smtp_connection_manager.h"
#include "smtp_connection.h"
#include "options.h"
#include "uti.h"
#include "rfc_date.h"
#include "aliases.h"
#include "param_parser.h"
#include "header_parser.h"
#include "rfc822date.h"
#include "aspf.h"
#include "ip_options.h"
#include "aspf.h"
#include "log.h"
#include "yield.hpp"

using namespace y::net;


smtp_connection::smtp_connection(boost::asio::io_service &_io_service, smtp_connection_manager &_manager, boost::asio::ssl::context& _context)
        : io_service_(_io_service),
          m_ssl_socket(_io_service, _context),
          m_manager(_manager),
          m_connected_ip(boost::asio::ip::address_v4::any()),
          m_resolver(_io_service),
          m_smtp_delivery_pending(false),
          m_so_check_pending(false),
          m_dkim_status(dkim_check::DKIM_NONE),
          strand_(_io_service),
          m_envelope(new envelope()),
          m_timer(_io_service),
          m_timer_spfdkim(_io_service),
          m_read_pending_(false),
          m_error_count(0),
          authenticated_(false)
{
}

smtp_connection::~smtp_connection()
{
}

template <class Socket, class Response>
void smtp_connection::async_say_goodbye(Socket& s, Response& r)
{
    boost::asio::async_write(s, r,
            strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request,
                            shared_from_this(),
                            boost::asio::placeholders::error)));
}

boost::asio::ip::tcp::socket& smtp_connection::socket()
{
    return m_ssl_socket.next_layer();
}

void smtp_connection::start( bool _force_ssl )
{
#if defined(HAVE_PA_ASYNC_H)
    m_pa_timer.start();
#endif

    force_ssl_ = _force_ssl;

    m_connected_ip = socket().remote_endpoint().address();

    m_max_rcpt_count = g_config.m_max_rcpt_count;

    ip_options_config::ip_options_t opt;

    if (g_ip_config.check(m_connected_ip.to_v4(), opt))
    {
        m_max_rcpt_count = opt.m_rcpt_count;
    }

    m_session_id = envelope::generate_new_id();

    m_timer_value = g_config.m_smtpd_cmd_timeout;

    boost::asio::ip::tcp::endpoint ep(m_connected_ip, 0);

    m_remote_host_name =  m_connected_ip.to_string();

    m_resolver.async_resolve( rev_order_av4_str(m_connected_ip.to_v4(), "in-addr.arpa"),
            dns::type_ptr, strand_.wrap(boost::bind(&smtp_connection::handle_back_resolve,
                            shared_from_this(), _1, _2)));
}

void smtp_connection::handle_back_resolve(const boost::system::error_code& ec, dns::resolver::iterator it)
{
    m_remote_host_name.clear();

    if (ec == boost::asio::error::operation_aborted)
        return;

    if (!ec)
    {
        if (const boost::shared_ptr<dns::ptr_resource> ptr = boost::dynamic_pointer_cast<dns::ptr_resource>(*it))
            m_remote_host_name = unfqdn( ptr->pointer() );
    }

    if (m_remote_host_name.empty())
        m_remote_host_name = "unknown";

    g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: connect from %2%[%3%]") % m_session_id % m_remote_host_name % m_connected_ip.to_string()));

    if (g_config.m_rbl_active)
    {
        m_rbl_check.reset(new rbl_check(io_service_));

        std::istringstream is(g_config.m_rbl_hosts);

        for (std::istream_iterator<std::string> it(is); it != std::istream_iterator<std::string>(); )
        {
            m_rbl_check->add_rbl_source(*it);
            it++;
        }

        m_rbl_check->start(m_connected_ip.to_v4(), bind(&smtp_connection::start_proto, shared_from_this()));
    }
    else
    {
        start_proto();
    }
}

void smtp_connection::start_proto()
{
    m_proto_state = STATE_START;
    restart_timeout();

    ssl_state_ = ssl_none;

    add_new_command("rcpt", &smtp_connection::smtp_rcpt);
    add_new_command("mail", &smtp_connection::smtp_mail);
    add_new_command("data", &smtp_connection::smtp_data);
    add_new_command("ehlo", &smtp_connection::smtp_ehlo);
    add_new_command("helo", &smtp_connection::smtp_helo);
    add_new_command("quit", &smtp_connection::smtp_quit);
    add_new_command("rset", &smtp_connection::smtp_rset);
    add_new_command("noop", &smtp_connection::smtp_noop);

    std::string tls_flag = "NOTLS";

    if (g_config.m_use_tls && !force_ssl_)
    {
        add_new_command("starttls", &smtp_connection::smtp_starttls);
        std::string tls_flag = "TLS";
    }

#ifdef ENABLE_AUTH_BLACKBOX
    if (g_config.m_use_auth)
    {
        add_new_command("auth", &smtp_connection::smtp_auth);

        auth_.initialize(m_connected_ip.to_v4().to_string());
    }
#endif // ENABLE_AUTH_BLACKBOX

    std::ostream response_stream(&m_response);

    std::string rbl_status;
    std::string error;

    if (m_rbl_check && m_rbl_check->get_status(rbl_status))
    {
        if (m_rbl_check)
            m_rbl_check->stop();

        m_rbl_check.reset(new rbl_check(io_service_));

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: reject: CONNECT from %2%[%3%]: %4%; proto=SMTP, flags=%5%")
                        % m_session_id % m_remote_host_name % m_connected_ip.to_v4().to_string() % rbl_status % tls_flag));

        response_stream << rbl_status;

        if (force_ssl_)
        {
            ssl_state_ = ssl_active;

    	    m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
            	    strand_.wrap(boost::bind(&smtp_connection::handle_start_hello_write, shared_from_this(),
                                boost::asio::placeholders::error, true)));
        }
        else
        {
    	    boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
	}

    }
    else if (m_manager.start(shared_from_this(), g_config.m_client_connection_count_limit, g_config.m_connection_count_limit, error))
    {
        response_stream << "220 " << boost::asio::ip::host_name() << " " << (g_config.m_smtp_banner.empty() ? "Ok" : g_config.m_smtp_banner) << "\r\n";

        if (force_ssl_)
        {
            ssl_state_ = ssl_active;

    	    m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
            	    strand_.wrap(boost::bind(&smtp_connection::handle_start_hello_write, shared_from_this(),
                                boost::asio::placeholders::error, false)));

	}
	else
	{

    	    boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request,
                                shared_from_this(), boost::asio::placeholders::error)));
	}
    }
    else
    {
        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: reject: CONNECT from %2%[%3%]: %4%; proto=SMTP, flags=%5%")
                        % m_session_id % m_remote_host_name % m_connected_ip.to_v4().to_string()  % error % tls_flag));

        response_stream << error;

        if (force_ssl_)
        {
            ssl_state_ = ssl_active;

    	    m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
            	    strand_.wrap(boost::bind(&smtp_connection::handle_start_hello_write, shared_from_this(),
                                boost::asio::placeholders::error, true)));
	}
	else
	{

    	    boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
	}

    }
}

void smtp_connection::handle_start_hello_write(const boost::system::error_code& _error, bool _close)
{
    if (!_error)
    {
	if (_close)
	{
            if (ssl_state_ == ssl_active)
            {
                async_say_goodbye(m_ssl_socket, m_response);
            }
            else
            {
    		boost::asio::async_write(socket(), m_response,
            	    strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
	    }

	}
	else
	{
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

    }
}


void smtp_connection::start_read()
{
    if ((m_proto_state == STATE_CHECK_RCPT) || (m_proto_state == STATE_CHECK_DATA) || (m_proto_state == STATE_CHECK_AUTH) || (m_proto_state == STATE_CHECK_MAILFROM))
    {
        m_timer.cancel();               // wait for check to complete
        return;
    }

    restart_timeout();

    if (std::size_t unread_size = buffers_.size() - m_envelope->orig_message_token_marker_size_)
    {
        handle_read_helper(unread_size);
    }
    else if (!m_read_pending_)
    {
        if (ssl_state_ == ssl_active)
        {
            m_ssl_socket.async_read_some(buffers_.prepare(512),
                    strand_.wrap(boost::bind(&smtp_connection::handle_read, shared_from_this(),
                                    boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
        }
        else
        {
            socket().async_read_some(buffers_.prepare(512),
                    strand_.wrap(boost::bind(&smtp_connection::handle_read, shared_from_this(),
                                    boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
        }

        m_read_pending_ = true;
    }
}

// Parses text as part of the message data from [b, e) input range.
/**
 * Returns:
 *   true, if futher input required and we have nothing to output
 *   false, otherwise
 * parsed: iterator pointing directly past the parsed and processed part of the input range;
 * read: iterator pointing directly past the last read character of the input range (anything in between [parsed, read) is a prefix of a eom token);
 */
bool smtp_connection::handle_read_data_helper(const yconst_buffers_iterator& b, const yconst_buffers_iterator& e,
        yconst_buffers_iterator& parsed, yconst_buffers_iterator& read)
{
    yconst_buffers_iterator eom;
    bool eom_found = eom_parser_.parse(b, e, eom, read);

    if (g_config.m_remove_extra_cr)
    {
        yconst_buffers_iterator p = b;
        yconst_buffers_iterator crlf_b, crlf_e;
        bool crlf_found = false;
        while (p != eom)
        {
            crlf_found = crlf_parser_.parse(p, eom, crlf_b, crlf_e);
            if (crlf_found)
            {
                if (crlf_e - crlf_b > 2) // \r{2+}\n
                {
                    m_envelope->orig_message_size_ += append(p, crlf_b, m_envelope->orig_message_);        // text preceeding \r+\n token
                    m_envelope->orig_message_size_ += append(crlf_e-2, crlf_e, m_envelope->orig_message_); // \r\n
                    parsed = crlf_e;
                }
                else
                {
                    m_envelope->orig_message_size_ += append(p, crlf_e, m_envelope->orig_message_);
                    parsed = crlf_e;
                }
            }
            else
            {
                m_envelope->orig_message_size_ += append(p, crlf_b, m_envelope->orig_message_);
                parsed = crlf_b;
            }
            p = crlf_e;
        }
    }
    else
    {
        m_envelope->orig_message_size_ += append(b, eom, m_envelope->orig_message_);
        parsed = eom;
    }

    if (eom_found)
    {
        m_proto_state = STATE_CHECK_DATA;
        io_service_.post(strand_.wrap(bind(&smtp_connection::start_check_data, shared_from_this())));

        parsed = read;
        return false;
    }
    else
    {
        return true;
    }
}

// Parses and executes commands from [b, e) input range.
/**
 * Returns:
 *   true, if futher input required and we have nothing to output
 *   false, otherwise
 * parsed: iterator pointing directly past the parsed and processed part of the input range;
 * read: iterator pointing directly past the last read character of the input range (anything in between [parsed, read) is a prefix of a command);
*/
bool smtp_connection::handle_read_command_helper(const yconst_buffers_iterator& b, const yconst_buffers_iterator& e,
        yconst_buffers_iterator& parsed, yconst_buffers_iterator& read)
{
    if ((read = std::find(b, e, '\n')) != e)
    {
        std::string command (parsed, read);
        parsed = ++read;

        std::ostream response_stream(&m_response);

#ifdef ENABLE_AUTH_BLACKBOX
        bool res = (m_proto_state == STATE_AUTH_MORE) ?
                continue_smtp_auth(command, response_stream) :
                execute_command(command, response_stream);
#else
        bool res = execute_command(command, response_stream);
#endif // ENABLE_AUTH_BLACKBOX

        if (res)
        {
            switch (ssl_state_)
            {
                case ssl_none:
                    boost::asio::async_write(socket(), m_response,
                            strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                            boost::asio::placeholders::error)));
                    break;

                case ssl_hand_shake:
                    boost::asio::async_write(socket(), m_response,
                            strand_.wrap(boost::bind(&smtp_connection::handle_ssl_handshake, shared_from_this(),
                                            boost::asio::placeholders::error)));
                    break;

                case ssl_active:
                    boost::asio::async_write(m_ssl_socket, m_response,
                            strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                            boost::asio::placeholders::error)));
                    break;
            }

        }
        else
        {
            if (ssl_state_ == ssl_active)
            {
                async_say_goodbye(m_ssl_socket, m_response);
            }
            else
            {
                boost::asio::async_write(socket(), m_response,
                        strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                        boost::asio::placeholders::error)));
            }
        }
        return false;
    }
    return true;
}

// Parses the first size characters of buffers_.data().
void smtp_connection::handle_read_helper(std::size_t size)
{
    yconst_buffers bufs = buffers_.data();
    yconst_buffers_iterator b = ybuffers_begin(bufs);
    yconst_buffers_iterator e = b + size;
    yconst_buffers_iterator bb = b + m_envelope->orig_message_token_marker_size_;
    assert (bb < e);

    yconst_buffers_iterator read = bb;
    yconst_buffers_iterator parsed = b;
    bool cont = (m_proto_state == STATE_BLAST_FILE)
            ? handle_read_data_helper(bb, e, parsed, read)
            : handle_read_command_helper(bb, e, parsed, read);

    std::ptrdiff_t parsed_len = parsed - b;
    m_envelope->orig_message_token_marker_size_ = read - parsed;

    buffers_.consume(parsed_len);

    if (cont)
        start_read();
}

void smtp_connection::handle_read(const boost::system::error_code& _err, std::size_t size)
{
    m_read_pending_ = false;

    if (size == 0)
    {
        m_manager.stop(shared_from_this());
        return;
    }

    if (!_err)
    {
        buffers_.commit(size);
        handle_read_helper(buffers_.size());
    }
    else
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            m_manager.stop(shared_from_this());
        }
    }
}

void smtp_connection::start_check_data()
{
    m_check_data.m_session_id = m_session_id;
    m_check_data.m_remote_ip = m_connected_ip.to_string();
    m_check_data.m_helo_host = m_helo_host;
    m_check_data.m_remote_host = m_remote_host_name;
    m_check_data.m_result = check::CHK_ACCEPT;
    m_check_data.m_answer = "";

    m_timer.cancel();

    if (m_envelope->orig_message_size_ > g_config.m_message_size_limit)
    {
        m_error_count++;

        m_check_data.m_result = check::CHK_REJECT;
        m_check_data.m_answer =  "552 5.3.4 Error: message file too big;";

        g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-RECV: warning: queue file size limit exceeded") % m_check_data.m_session_id %  m_envelope->m_id ));

        end_check_data();
    }
    else
    {
        //        start_so_avir_checks();
        smtp_delivery_start();
    }
}

struct smtp_connection::handle_greylisting_mark
        : private coroutine
{
    boost::shared_ptr<smtp_connection> c;
    envelope::rcpt_list_t::iterator rcpt_beg;
    envelope::rcpt_list_t::iterator rcpt_end;
    bool someone_failed;
    boost::weak_ptr<envelope> env;

    handle_greylisting_mark(
        boost::shared_ptr<smtp_connection> cc,
        envelope::rcpt_list_t::iterator b,
        envelope::rcpt_list_t::iterator e)
            : c(cc),
              rcpt_beg(b),
              rcpt_end(e),
              someone_failed(false),
              env(c->m_envelope)
    {
    }

    typedef boost::system::error_code error_code;
    typedef greylisting_client::hostlist hostlist;

    void operator()(const error_code& ec = error_code(),
            hostlist::value_type host = hostlist::value_type())
    {
        if (env.expired())
            return;

        //        assert(rcpt_beg != rcpt_end);
        if (rcpt_beg == rcpt_end)
        {
            c->m_check_data.m_result = check::CHK_TEMPFAIL;
            c->m_check_data.m_answer =  "451 4.7.1 Service unavailable - try again later";
            return c->end_check_data();
        }

        reenter(*this)
        do
        {
            assert (rcpt_beg->gr_check_);

            yield return
                    rcpt_beg->gr_check_->mark(
                        str(boost::format("%1%-%2%")
                                % c->m_session_id % rcpt_beg->m_suid),
                        c->strand_.wrap(*this));

            if (ec == boost::asio::error::operation_aborted)
                return;

            if (ec == greylisting_client::too_early
                    || ec == greylisting_client::too_late)
                someone_failed = true;

            g_log.msg(MSG_NORMAL,
                    str(boost::format("%1%-%2%-GR %3% status:%4%; host=%5%")
                            % c->m_session_id
                            % c->m_envelope->m_id
                            % rcpt_beg->m_suid
                            % ec.message()
                            % rcpt_beg->gr_check_->info().host));

        } while (++rcpt_beg != rcpt_end);

        assert(rcpt_beg == rcpt_end);

        if (someone_failed)
        {
            c->m_check_data.m_result = check::CHK_TEMPFAIL;
            c->m_check_data.m_answer =  "451 4.7.1 Sorry, the service is currently unavailable. Please come back later.";
            return c->end_check_data();
        }
        return c->smtp_delivery_start();
    }
};

struct smtp_connection::handle_rc_put
        : private coroutine
{
    boost::shared_ptr<smtp_connection> c;
    envelope::rcpt_list_t::iterator rcpt_beg;
    envelope::rcpt_list_t::iterator rcpt_end;
    bool someone_failed;
    boost::weak_ptr<envelope> env;

    handle_rc_put(
        boost::shared_ptr<smtp_connection> cc,
        envelope::rcpt_list_t::iterator b,
        envelope::rcpt_list_t::iterator e)
            : c(cc),
              rcpt_beg(b),
              rcpt_end(e),
              someone_failed(false),
              env(c->m_envelope)
    {
    }

    typedef boost::system::error_code error_code;

    void operator()(const error_code& ec = error_code(),
            boost::optional<rc_result> rc = boost::optional<rc_result>())
    {
        if (env.expired())
            return;

        //        assert(rcpt_beg != rcpt_end);
        if (rcpt_beg == rcpt_end)
        {
            c->m_check_data.m_result = check::CHK_TEMPFAIL;
            c->m_check_data.m_answer =  "451 4.7.1 Service unavailable - try again later";
            return c->end_check_data();
        }

        boost::shared_ptr<rc_check> q = rcpt_beg->rc_check_;

        reenter(*this)
        do
        {
            if (!rcpt_beg->rc_check_) // case of multiple aliases
                continue;

            yield return
                    rcpt_beg->rc_check_->put(
                        c->strand_.wrap(*this),
                        c->m_envelope->orig_message_size_);

            if (ec == boost::asio::error::operation_aborted)
                return;

            if (!rc || rc->ok)
            {
                if (!rc)
                {
                    g_log.msg(MSG_NORMAL,
                            str(boost::format(
                                "%1%-RC-DATA failed to "
                                "commit iprate PUT check because of the server"
                                " being down or bad config; ignored (host=[%2%], rcpt=[%3%])") %
                                    c->m_session_id % q->get_hostname() % q->get_email())
                              );
                }
            }
            else
            {
                someone_failed = true;
                break;
            }
        } while (++rcpt_beg != rcpt_end);

        if (someone_failed)
        {
                const rc_parameters& p = q->get_parameters();
                g_log.msg(MSG_NORMAL, str(boost::format("%1%-RC-DATA "
                                        "the recipient has exceeded their message rate"
                                        " limit (from=%2%,rcpt=<%3%>,uid=%4%,host=[%5%])") %
                                c->m_session_id %
                                c->m_smtp_from %
                                q->get_email() %
                                p.ukey %
                                q->get_hostname()));

                c->m_check_data.m_answer = str(boost::format("451 4.5.1 The "
                                "recipient <%1%> has exceeded their message rate "
                                "limit. Try again later.") % q->get_email());
                c->m_check_data.m_result = check::CHK_TEMPFAIL;

            c->m_check_data.m_result = check::CHK_TEMPFAIL;
            c->m_check_data.m_answer =
                    "451 4.7.1 Sorry, the service is currently unavailable. Please come back later.";
            return c->end_check_data();
        }

        c->m_check_data.m_result = check::CHK_ACCEPT;
        return c->smtp_delivery_start();
    }
};


struct smtp_connection::handle_greylisting_probe
        : private coroutine
{
    boost::shared_ptr<smtp_connection> c;
    envelope::rcpt_list_t::iterator rcpt_beg;
    envelope::rcpt_list_t::iterator rcpt_end;
    weak_ptr<envelope> env;

    handle_greylisting_probe(
        boost::shared_ptr<smtp_connection> cc,
        envelope::rcpt_list_t::iterator b,
        envelope::rcpt_list_t::iterator e)
            : c(cc),
              rcpt_beg(b),
              rcpt_end(e),
              env(c->m_envelope)
    {
    }

    typedef boost::system::error_code error_code;
    typedef greylisting_client::hostlist hostlist;
    typedef greylisting_client::iter_range_t iter_range_t;

    void operator()(const error_code& ec = error_code(),
            hostlist::value_type host = hostlist::value_type())
    {
        if (env.expired())
            return;

        //        assert(rcpt_beg != rcpt_end);
        if (rcpt_beg == rcpt_end)
            return c->avir_check_data();

        reenter(*this)
        do
        {
            rcpt_beg->gr_check_.reset(
                new greylisting_client(c->strand_.get_io_service(),
                        g_config.greylisting_,
                        g_config.greylisting_.hosts));

            yield return
                    rcpt_beg->gr_check_->probe(
                        greylisting_client::key(
                            c->m_connected_ip,
                            c->m_smtp_from,
                            boost::lexical_cast<std::string>(rcpt_beg->m_suid),
                            c->gr_headers_,
                            iter_range_t(c->m_envelope->orig_message_body_beg_,
                                    ybuffers_end(c->m_envelope->orig_message_))),
                        str(boost::format("%1%-%2%")
                                % c->m_session_id % rcpt_beg->m_suid),
                        c->strand_.wrap(*this));

            if (ec == boost::asio::error::operation_aborted)
                return;

            if (rcpt_beg->gr_check_->info().valid
                    && rcpt_beg->gr_check_->info().n > 0)
                c->m_envelope->m_spam = true;

        } while (++rcpt_beg != rcpt_end);

        assert(rcpt_beg == rcpt_end);

        if (!c->m_envelope->m_spam
                || g_config.enable_so_after_greylisting_)
        {
            if (g_config.m_so_check
                    && c->m_envelope->orig_message_size_ > 0)
            {
                c->m_so_check.reset(new so_client(c->io_service_, &g_so_switch));
                return c->m_so_check->start(
                    c->m_check_data,
                    c->strand_.wrap(bind(&smtp_connection::handle_so_check, c)),
                    c->m_envelope, c->m_smtp_from, c->m_spf_result, c->m_spf_expl);
            }
        }
        else if (c->m_envelope->m_spam)
            append("X-Yandex-Spam: 4\r\n", c->m_envelope->added_headers_);

        return c->avir_check_data();
    }
};

struct smtp_connection::handle_rc_get
        : private coroutine
{
    boost::shared_ptr<smtp_connection> c;
    weak_ptr<envelope> env;
    boost::shared_ptr<rc_check> q;

    handle_rc_get(
        boost::shared_ptr<smtp_connection> cc)
            : c(cc),
              env(c->m_envelope),
              q()
    {
    }

    typedef boost::system::error_code error_code;

    void operator()(const error_code& ec = error_code(),
            boost::optional<rc_result> rc = boost::optional<rc_result>())
    {
        if (env.expired())
            return;

        reenter(*this)
        {
            q.reset(
                new rc_check(c->io_service_,
                        c->m_check_rcpt.m_rcpt,
                        c->m_check_rcpt.m_uid,
                        g_config.m_rc_host_list,
                        g_config.m_rc_timeout));

            yield return
                    q->get(c->strand_.wrap(*this));

            if (ec == boost::asio::error::operation_aborted)
                return;


            if (!c->m_envelope->m_rcpt_list.empty())
                c->m_proto_state = STATE_RCPT_OK;
            else
                c->m_proto_state = STATE_AFTER_MAIL;

            if (!rc && ec != boost::asio::error::operation_aborted)
            {
                g_log.msg(MSG_NORMAL, str(boost::format("%1%-RC-RCPT failed to "
                                        "commit iprate check in GET because of the server"
                                        " being down or bad config; ignored (host=[%2%], rcpt=[%3%])") %
                                c->m_session_id % q->get_hostname() % c->m_check_rcpt.m_rcpt));
            }
            else if (!rc->ok)
            {
                c->m_error_count++;

                const rc_parameters& p = q->get_parameters();
                g_log.msg(MSG_NORMAL, str(boost::format("%1%-RC-RCPT "
                                        "the recipient has exceeded their message rate"
                                        " limit (from=%2%,rcpt=<%3%>,uid=%4%,host=[%5%])") %
                                c->m_session_id % c->m_smtp_from %
                                c->m_check_rcpt.m_rcpt % p.ukey % q->get_hostname()));

                std::string result = str(boost::format("451 4.5.1 The "
                                "recipient <%1%> has exceeded their message rate "
                                "limit. Try again later.") % c->m_check_rcpt.m_rcpt);

                std::ostream response_stream(&c->m_response);
                response_stream << result;

                boost::asio::async_write(c->socket(), c->m_response,
                        c->strand_.wrap(boost::bind(&smtp_connection::handle_write_request,
                                        c, boost::asio::placeholders::error)));
                return;
            }

            // Add this recipient
            c->m_proto_state = STATE_RCPT_OK;
            c->m_envelope->m_no_local_relay |= g_aliases.process(c->m_check_rcpt.m_rcpt,
                    c->m_check_rcpt.m_suid,
                    boost::bind(&handle_rc_get::add_rcpt, *this, _1, _2));
            q.reset();

            std::string result = str(boost::format(
                "250 2.1.5 <%1%> recipient ok\r\n") % c->m_check_rcpt.m_rcpt);
            std::ostream response_stream(&c->m_response);

            response_stream << result;

            if (c->ssl_state_ == ssl_active)
            {
                boost::asio::async_write(c->m_ssl_socket, c->m_response,
                        c->strand_.wrap(
                            boost::bind(&smtp_connection::handle_write_request, c,
                                    boost::asio::placeholders::error)));
            }
            else
            {
                boost::asio::async_write(c->socket(), c->m_response,
                        c->strand_.wrap(
                            boost::bind(&smtp_connection::handle_write_request, c,
                                        boost::asio::placeholders::error)));
            }
        }
    }

  private:
    void add_rcpt(const std::string& rcpt, long long unsigned suid)
    {
        envelope::rcpt_list_t::iterator it =
                c->m_envelope->add_recipient(rcpt, suid, c->m_check_rcpt.m_uid);
        if (it != c->m_envelope->m_rcpt_list.end())
        {
            it->rc_check_ = q;
            q.reset(); // we don't want to RC a user more than once if she has multiple aliases
        }
    }
};

void smtp_connection::start_so_avir_checks()
{
    if (spf_check_ && spf_check_->is_inprogress())  // wait for SPF check to complete
    {
        m_so_check_pending = true;
        return;
    }
    m_so_check_pending = false;

    if (m_so_check)
        m_so_check->stop();

    if (g_config.use_greylisting_ && g_config.m_so_check)
    {
        return handle_greylisting_probe(shared_from_this(),
                m_envelope->m_rcpt_list.begin(),
                m_envelope->m_rcpt_list.end())();
    }

    if (g_config.m_so_check && m_envelope->orig_message_size_ > 0)
    {
        m_so_check.reset(new so_client(io_service_, &g_so_switch));
        m_so_check->start(m_check_data,
                strand_.wrap(bind(&smtp_connection::handle_so_check, shared_from_this())),
                m_envelope, m_smtp_from, m_spf_result, m_spf_expl);
    }
    else
    {
        avir_check_data();
    }
}

void smtp_connection::handle_so_check()
{
    if (m_so_check)
    {
        m_check_data = m_so_check->check_data();
        m_so_check->stop();
        m_so_check.reset();
    }
    avir_check_data();
}

void smtp_connection::handle_avir_check()
{
    if (m_avir_check)
    {
        m_check_data = m_avir_check->check_data();
        m_avir_check->stop();
        m_avir_check.reset();
    }
    smtp_delivery_start();
}

void smtp_connection::avir_check_data()
{
    if ( m_check_data.m_result == check::CHK_ACCEPT )
    {
        if (g_config.m_av_check && m_envelope->orig_message_size_ > 0)
        {
            m_avir_check.reset(new avir_client(io_service_, &g_av_switch));
            m_avir_check->start(m_check_data,
                    strand_.wrap(
                        bind(&smtp_connection::handle_avir_check,
                                shared_from_this())), m_envelope
                                );
        }
        else
            smtp_delivery_start();
    }
    else
    {
        end_check_data();
    }

}

void smtp_connection::handle_spf_timeout(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (spf_check_.get())
    {
        spf_check_->stop();
    }

    spf_check_.reset();

    if (m_so_check_pending)
    {
        start_so_avir_checks();
    }
}

void smtp_connection::handle_dkim_timeout(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted)
        return;
    if (dkim_check_)
        dkim_check_->stop();
    dkim_check_.reset();
    if (m_smtp_delivery_pending)
        smtp_delivery_start();
}

namespace
{
template <class Range>
void log_message_id(Range message_id, const string& session_id, const string& envelope_id)
{
    g_log.msg(MSG_NORMAL,
            str(boost::format("%1%-%2%-RECV: message-id=%3%") % session_id % envelope_id % message_id));
}

void handle_parse_header(const header_iterator_range_t& name, const header_iterator_range_t& header,
        const header_iterator_range_t& value, list <header_iterator_range_t>& h,
        header_iterator_range_t& message_id, boost::unordered_set<string>& unique_h,
        const boost::unordered_set<string>& rem_h, greylisting_client::headers& gr_headers)
{
    string lname; // lower-cased header name
    size_t name_sz = name.size();
    lname.reserve(name_sz);
    std::transform(name.begin(), name.end(), back_inserter(lname), ::tolower);
    unique_h.insert( lname );

    if ( !strcmp(lname.c_str(), "message-id") )
    {
        message_id = value;
        gr_headers.messageid = message_id;
    }
    else if ( !strcmp(lname.c_str(), "to") )
        gr_headers.to = value;
    else if ( !strcmp(lname.c_str(), "from") )
        gr_headers.from = value;
    else if ( !strcmp(lname.c_str(), "subject") )
        gr_headers.subject = value;
    else if ( !strcmp(lname.c_str(), "date") )
        gr_headers.date = value;

    // add a header field to the list only if we don't have to remove it from the message
    if (!g_config.m_remove_headers || rem_h.find(lname) == rem_h.end())
        h.push_back( header );
}
}

void smtp_connection::smtp_delivery_start()
{
    if (dkim_check_ && dkim_check_->is_inprogress()) // wait for DKIM check to complete
    {
        m_smtp_delivery_pending = true;
        return;
    }
    m_smtp_delivery_pending = false;

    bool continue_delivery = false;
    bool skip_so_avir_checks = false;

    yconst_buffers& orig_m = m_envelope->orig_message_;
    yconst_buffers& alt_m = m_envelope->altered_message_;
    yconst_buffers& orig_h = m_envelope->orig_headers_;
    yconst_buffers& added_h = m_envelope->added_headers_;

    reenter (m_envelope->smtp_delivery_coro_)
    {
        for (;;)
        {
            has_dkim_headers_ = false;

            if (m_check_data.m_result == check::CHK_ACCEPT)
            {
                // alter headers & compose the resulting message here
                typedef list<header_iterator_range_t> hl_t; // header fields subset from the original message for the composed message
                hl_t h;
                header_iterator_range_t message_id;
                boost::unordered_set<std::string> unique_h;
                header_iterator_range_t::iterator b = ybuffers_begin(orig_m);
                header_iterator_range_t::iterator e = ybuffers_end(orig_m);
                header_iterator_range_t r (b, e);
                m_envelope->orig_message_body_beg_ = parse_header(r,
                        boost::bind(&handle_parse_header, _1, _2, _3,
                                boost::ref(h), boost::ref(message_id), boost::ref(unique_h),
                                boost::cref(g_config.m_remove_headers_set),
                                boost::ref(gr_headers_)));

                shared_const_chunk crlf (new chunk_csl("\r\n"));
                for (hl_t::const_iterator it=h.begin(); it!=h.end(); ++it)
                {
                    // append existing headers
                    append(it->begin(), it->end(), orig_h);
                    append(crlf, orig_h); // ###
                }

                // add missing headers
                if ( unique_h.find("message-id") == unique_h.end() )
                {
                    time_t rawtime;
                    struct tm * timeinfo;
                    char timeid [1024];
                    time ( &rawtime );
                    timeinfo = localtime ( &rawtime );
                    strftime (timeid, sizeof timeid, "%Y%m%d%H%M%S",timeinfo);

                    string message_id_str = str( boost::format("<%1%.%2%@%3%>")
                            % timeid % m_envelope->m_id % boost::asio::ip::host_name());     // format: <20100406110540.C671D18D007F@mxback1.mail.yandex.net>

                    append(str(boost::format("Message-Id: %1%\r\n") % message_id_str), added_h);

                    log_message_id(message_id_str, m_check_data.m_session_id, m_envelope->m_id); // log composed message-id
                }
                else
                {
                    log_message_id(message_id, m_check_data.m_session_id, m_envelope->m_id); // log original message-id
                }

                if ( unique_h.find("date") == unique_h.end() )
                {
                    char timestr[256];
                    char zonestr[256];
                    time_t rawtime;
                    time (&rawtime);
                    append(str(boost::format("Date: %1%")
                                    % rfc822date(&rawtime, timestr, sizeof timestr, zonestr, sizeof zonestr)
                               ),
                            added_h);
                }
                if ( unique_h.find("from") == unique_h.end() )
                {
                    append("From: MAILER-DAEMON\r\n", added_h);
                }
                if ( unique_h.find("to") == unique_h.end() )
                {
                    append("To: undisclosed-recipients:;\r\n", added_h);
                }
                if ( g_config.so_trust_xyandexspam_
                        && unique_h.find("x-yandex-spam") != unique_h.end() )
                {
                    skip_so_avir_checks = true;
                }

                has_dkim_headers_ = unique_h.find("dkim-signature") != unique_h.end();

                continue_delivery = true;
                break;
            }
            else
            {
                end_check_data();
                return;
            }
        }

        if (continue_delivery)
        {
            if (!skip_so_avir_checks)
                yield start_so_avir_checks();

            if (m_check_data.m_result != check::CHK_ACCEPT)
                return end_check_data();

            if (m_envelope->m_spam
                    &&  g_config.use_greylisting_)
            {
                yield return
                        handle_greylisting_mark (
                            shared_from_this(),
                            m_envelope->m_rcpt_list.begin(),
                            m_envelope->m_rcpt_list.end())();
            }

            if (g_config.m_rc_check)
            {
                yield return
                        handle_rc_put (
                            shared_from_this(),
                            m_envelope->m_rcpt_list.begin(),
                            m_envelope->m_rcpt_list.end())();
            }

            if (has_dkim_headers_)
            {
                dkim_check_.reset( new dkim_check);
                m_smtp_delivery_pending = true;

                m_timer_spfdkim.expires_from_now(
                    boost::posix_time::seconds(g_config.m_dkim_timeout));
                m_timer_spfdkim.async_wait(
                    strand_.wrap(boost::bind(&smtp_connection::handle_dkim_timeout,
                                    shared_from_this(), boost::asio::placeholders::error)));

                m_dkim_status = dkim_check::DKIM_NONE;
                m_dkim_identity.clear();
                yield dkim_check_->start(
                    strand_.get_io_service(),
                    dkim_parameters(ybuffers_begin(orig_m),
                            m_envelope->orig_message_body_beg_,
                            ybuffers_end(orig_m)),
                    strand_.wrap(
                        boost::bind(&smtp_connection::handle_dkim_check,
                                shared_from_this(), _1, _2)));

                m_smtp_delivery_pending = false;
            }

            bool has_dkim = m_dkim_status != dkim_check::DKIM_NONE;
            bool has_spf = m_spf_result && m_spf_expl;

            if (has_dkim || has_spf)
            {
                // add Authentication-Results header
                string ah;
                string dkim_identity;
                if (has_dkim && !m_dkim_identity.empty())
                    dkim_identity = str( boost::format(" header.i=%1%") % m_dkim_identity );
                if (has_dkim && has_spf)
                    ah = str(boost::format("Authentication-Results: %1%; spf=%2% (%3%) smtp.mail=%4%; dkim=%5%%6%\r\n")
                            % boost::asio::ip::host_name() % m_spf_result.get() % m_spf_expl.get() % m_smtp_from
                            % dkim_check::status(m_dkim_status) % dkim_identity);
                else if (has_spf)
                    ah = str(boost::format("Authentication-Results: %1%; spf=%2% (%3%) smtp.mail=%4%\r\n")
                            % boost::asio::ip::host_name() % m_spf_result.get() % m_spf_expl.get() % m_smtp_from);
                else
                    ah = str(boost::format("Authentication-Results: %1%; dkim=%2%%3%\r\n")
                            % boost::asio::ip::host_name() % dkim_check::status(m_dkim_status) % dkim_identity);

                g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-%3%")
                                % m_session_id % m_envelope->m_id % ah));

                append(ah, added_h);
            }

            shared_const_chunk crlf (new chunk_csl("\r\n"));
            append(added_h.begin(), added_h.end(), alt_m);
            append(orig_h.begin(), orig_h.end(), alt_m);
            append(crlf, alt_m);
            append(m_envelope->orig_message_body_beg_, ybuffers_end(orig_m), alt_m);

            if (m_smtp_client)
                m_smtp_client->stop();
            m_smtp_client.reset(new smtp_client(io_service_));

            if (g_config.m_use_local_relay && !(m_envelope->m_no_local_relay))
            {
                m_smtp_client->start(m_check_data, strand_.wrap(bind(&smtp_connection::end_lmtp_proto, shared_from_this())), m_envelope, g_config.m_local_relay_host, "LOCAL");
            }
            else
            {
                smtp_delivery();
            }
        }
    } // reenter
}

void smtp_connection::end_lmtp_proto()
{
    m_envelope->remove_delivered_rcpt();

    if (m_envelope->m_rcpt_list.empty())
    {
        end_check_data();
    }
    else
    {
        smtp_delivery();
    }
}

void smtp_connection::smtp_delivery()
{
    if (m_smtp_client)
    {
        m_smtp_client->stop();
    }
    m_smtp_client.reset(new smtp_client(io_service_));
    m_smtp_client->start(m_check_data, strand_.wrap(bind(&smtp_connection::end_check_data, shared_from_this())), m_envelope, g_config.m_relay_host, "SMTP");
}

void smtp_connection::end_check_data()
{
    if (m_smtp_client)
    {
        m_check_data = m_smtp_client->check_data();
        m_smtp_client->stop();
    }
    m_smtp_client.reset();

    m_proto_state = STATE_HELLO;

    std::ostream response_stream(&m_response);

    switch (m_check_data.m_result)
    {
        case check::CHK_ACCEPT:
        case check::CHK_DISCARD:
            response_stream << "250 2.0.0 Ok: queued on " << boost::asio::ip::host_name() << " as";
            break;

        case check::CHK_REJECT:
            if (!m_check_data.m_answer.empty())
            {
                response_stream << m_check_data.m_answer;
            }
            else
            {
                response_stream << "550 " << boost::asio::ip::host_name();
            }

            break;

        case check::CHK_TEMPFAIL:
            if (!m_check_data.m_answer.empty())
            {
                response_stream << m_check_data.m_answer;
            }
            else
            {
                response_stream << temp_error;
            }

            break;
    }

    response_stream << " " << m_session_id << "-" <<  m_envelope->m_id << "\r\n";

#if defined(HAVE_PA_ASYNC_H)
    pa::async_profiler::add(pa::smtp_client, m_remote_host_name, "smtp_client_session", m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop());
#endif

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

void smtp_connection::handle_write_request(const boost::system::error_code& _err)
{
    if (!_err)
    {
        if (m_error_count >= std::max(g_config.m_hard_error_limit, 1))
        {
            g_log.msg(MSG_NORMAL, str(boost::format("%1%: too many errors")
                            % m_session_id));

            std::ostream response_stream(&m_response);
            response_stream << "421 4.7.0 " << boost::asio::ip::host_name() << " Error: too many errors\r\n";
            boost::asio::async_write(socket(), m_response,
                    strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                    boost::asio::placeholders::error)));

            return;
        }

        start_read();
    }
    else
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            m_manager.stop(shared_from_this());
        }
    }
}

void smtp_connection::handle_last_write_request(const boost::system::error_code& _err)
{
    if (!_err)
    {
        try
        {
            socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            socket().close();
        }
        catch (boost::system::system_error &_err)
        {
        }
    }

    if (_err != boost::asio::error::operation_aborted)
    {
        m_manager.stop(shared_from_this());
    }
}

void smtp_connection::handle_ssl_handshake(const boost::system::error_code& _err)
{
    if (!_err)
    {
        ssl_state_ = ssl_active;

        m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    }
    else
    {
        if (_err != boost::asio::error::operation_aborted)
        {
            m_manager.stop(shared_from_this());
        }
    }
}

bool smtp_connection::execute_command(const std::string &_cmd, std::ostream &_response)
{
    std::string buffer(_cmd);

    if (g_config.m_debug_level > 0)
    {
        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: exec cmd='%2%'") % m_session_id % cleanup_str(_cmd)));
    }

    std::string::size_type pos = buffer.find_first_not_of( " \t" );

    if ( pos != std::string::npos )
        buffer.erase( 0, pos );    // Strip starting whitespace

    pos = buffer.find_last_not_of( " \t\r\n" );

    if ( pos != std::string::npos )
        buffer.erase( pos + 1 );    // .. and ending whitespace

    pos = buffer.find( ' ' );

    std::string command;

    std::string arg;

    if ( pos == std::string::npos )     // Split line into command and argument parts
    {
        command = buffer;
    }
    else
    {
        command = buffer.substr( 0, pos );
        arg = buffer.substr( pos + 1 );
    }

    std::transform(command.begin(), command.end(), command.begin(), ::tolower);

    proto_map_t::iterator func = m_proto_map.find(command);

    if (func != m_proto_map.end())
    {
        return (func->second)(this, arg, _response);
    }
    else
    {
        m_error_count++;
        _response << "502 5.5.2 Syntax error, command unrecognized.\r\n";
    }

    return true;
}

void smtp_connection::add_new_command(const char *_command, proto_func_t _func)
{
    m_proto_map[_command] = _func;
}

bool smtp_connection::smtp_quit( const std::string& _cmd, std::ostream &_response )
{
    _response << "221 2.0.0 Closing connection.\r\n";

    return false;
}

bool smtp_connection::smtp_noop ( const std::string& _cmd, std::ostream &_response )
{
    _response << "250 2.0.0 Ok\r\n";

    return true;
}

bool smtp_connection::smtp_starttls ( const std::string& _cmd, std::ostream &_response )
{
    ssl_state_ = ssl_hand_shake;

    _response << "220 Go ahead\r\n";

    return true;
}

bool smtp_connection::smtp_rset ( const std::string& _cmd, std::ostream &_response )
{
    if ( m_proto_state > STATE_START )
        m_proto_state = STATE_HELLO;

    m_envelope.reset(new envelope());

    _response << "250 2.0.0 Ok\r\n";

    return true;
}


bool smtp_connection::hello( const std::string &_host)
{
    if ( _host.empty() )
    {
        m_proto_state = STATE_START;
        return false;
    }

    m_proto_state = STATE_HELLO;

    m_helo_host = _host;

    return true;
}

bool smtp_connection::smtp_helo( const std::string& _cmd, std::ostream &_response )
{

    if ( hello( _cmd ) )
    {
        _response << "250 " << boost::asio::ip::host_name() << "\r\n";
        m_ehlo = false;
    }
    else
    {
        m_error_count++;

        _response << "501 5.5.4 HELO requires domain address.\r\n";
    }

    return true;
}

bool smtp_connection::smtp_ehlo( const std::string& _cmd, std::ostream &_response )
{
    std::string esmtp_flags("250-8BITMIME\r\n250-PIPELINING\r\n" );

    if (g_config.m_message_size_limit > 0)
    {
        esmtp_flags += str(boost::format("250-SIZE %1%\r\n") % g_config.m_message_size_limit);
    }

     if (g_config.m_use_tls && !force_ssl_)
    {
        esmtp_flags += "250-STARTTLS\r\n";
    }

#if ENABLE_AUTH_BLACKBOX
    if (g_config.m_use_auth)
    {
        esmtp_flags += "250-AUTH " + auth_.get_methods() + "\r\n";
    }
#endif // ENABLE_AUTH_BLACKBOX

    esmtp_flags += "250 ENHANCEDSTATUSCODES\r\n";

    if ( hello( _cmd ) )
    {
        _response << "250-" << boost::asio::ip::host_name() << "\r\n" << esmtp_flags;
        m_ehlo = true;
    }
    else
    {
        m_error_count++;

        _response << "501 5.5.4 EHLO requires domain address.\r\n";
    }

    return true;
}

std::string trim(const std::string &_str)
{
    if (_str.empty())
        return _str;

    std::string::size_type begin = _str.find_first_not_of(" \r\n\r");

    if (begin == std::string::npos)
    {
        begin = 0;
    }

    std::string::size_type end = _str.find_last_not_of(" \t\r\n") + 1;

    return _str.substr(begin, end - begin);
}

static std::string extract_addr(const std::string &_str)
{
    std::string buffer(_str);

    std::string::size_type beg = buffer.find("<");

    if (beg != std::string::npos)
    {
        std::string::size_type end = buffer.find(">", beg);

        if (end != std::string::npos)
        {
            buffer = buffer.substr(beg+1, (end-beg-1));
        }
    }

    return buffer;
}

static bool is_invalid(char _elem)
{
    return !((_elem >= 'a' && _elem <='z') || (_elem >= 'A' && _elem <='Z') ||
            (_elem >= '0' && _elem <='9') || _elem == '-' || _elem =='.' ||
            _elem == '_' || _elem == '@' || _elem == '%' || _elem == '+' ||
            _elem == '=' || _elem == '!' || _elem == '#' ||   _elem == '$' ||
            _elem == '"' ||   _elem == '*' ||   _elem == '-' || _elem == '/' ||
            _elem == '?' ||   _elem == '^' ||   _elem == '`' || _elem == '{' ||
            _elem == '}' ||   _elem == '|' ||   _elem == '~' || _elem == '&'
             ) ;
}

bool smtp_connection::smtp_rcpt( const std::string& _cmd, std::ostream &_response )
{
    if ( ( m_proto_state != STATE_AFTER_MAIL ) && ( m_proto_state != STATE_RCPT_OK ) )
    {
        m_error_count++;

        _response << "503 5.5.4 Bad sequence of commands.\r\n";
        return true;
    }

    if ( strncasecmp( _cmd.c_str(), "to:", 3 ) != 0 )
    {
        m_error_count++;

        _response << "501 5.5.4 Wrong param.\r\n";
        return true;
    }

    if (m_envelope->m_rcpt_list.size() >= m_max_rcpt_count)
    {
        m_error_count++;

        _response << "452 4.5.3 Error: too many recipients\r\n";
        return true;
    }

    std::string addr = trim(extract_addr(trim(_cmd.substr(3))));

    if (addr.empty())
    {
        m_error_count++;

        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        return true;
    }

    std::string::size_type perc_pos = addr.find("%");
    std::string::size_type dog_pos = addr.find("@");

    if (dog_pos == std::string::npos)
    {
        m_error_count++;

        _response << "504 5.5.2 Recipient address rejected: need fully-qualified address\r\n";
        return true;
    }

    if (std::count_if(addr.begin(), addr.end(), is_invalid) > 0)
    {
        m_error_count++;

        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        return true;
    }

    if (addr.find("%") != std::string::npos)                    // percent hack
    {
        if (g_config.m_allow_percent_hack)              // allow
        {
            addr = addr.substr(0, perc_pos) + "@" + addr.substr(perc_pos + 1, dog_pos - perc_pos - 1);
        }
        else
        {
            m_error_count++;

            _response << "501 5.1.3 Bad recipient address syntax.\r\n";
            return true;
        }
    }

    m_proto_state = STATE_CHECK_RCPT;

    m_check_rcpt.m_rcpt = addr;

    try
    {
        m_check_rcpt.m_remote_ip = m_connected_ip.to_string();
    }
    catch(...)
    {
        m_check_rcpt.m_remote_ip = "unknown";
    }

    m_check_rcpt.m_session_id = m_session_id;
    m_check_rcpt.m_result = check::CHK_ACCEPT;
    m_check_rcpt.m_suid = 0;
    m_check_rcpt.m_answer.clear();

    m_timer.cancel();

#ifdef ENABLE_AUTH_BLACKBOX
    if (g_config.m_bb_check)
    {
        if (m_bb_check_rcpt)
            m_bb_check_rcpt->stop();

        m_bb_check_rcpt.reset( new black_box_client_rcpt(io_service_, &g_bb_switch) );
        m_bb_check_rcpt->start( m_check_rcpt, strand_.wrap(bind(&smtp_connection::handle_bb_result, shared_from_this())), m_envelope );
    }
    else
    {
        socket().get_io_service().post( strand_.wrap(boost::bind(&smtp_connection::handle_bb_result_helper, shared_from_this())) );
    }
#else
    socket().get_io_service().post( strand_.wrap(boost::bind(&smtp_connection::handle_bb_result_helper, shared_from_this())) );
#endif // ENABLE_AUTH_BLACKBOX

    return true;
}

void smtp_connection::handle_bb_result_helper()
{
    std::string result = str(boost::format("250 2.1.5 <%1%> recipient ok\r\n") % m_check_rcpt.m_rcpt);

    switch (m_check_rcpt.m_result)
    {
        case check::CHK_ACCEPT:
            {
                if (!g_config.m_rc_check || !m_check_rcpt.m_suid || m_envelope->has_recipient(m_check_rcpt.m_suid))
                {
                    m_proto_state = STATE_RCPT_OK;
                    m_envelope->m_no_local_relay |= g_aliases.process(m_check_rcpt.m_rcpt,
                            m_check_rcpt.m_suid,  boost::bind(&envelope::add_recipient, m_envelope, _1, _2, m_check_rcpt.m_uid));
                }
                else
                {
                    // perform rc check
                    return handle_rc_get(shared_from_this())();
                }
            }

        case check::CHK_DISCARD:
            break;

        case check::CHK_REJECT:
            m_error_count++;

            result = "550 5.7.1 No such user!\r\n";
            break;

        case check::CHK_TEMPFAIL:
            m_error_count++;

            result = "450 4.7.1 No such user!\r\n";
            break;
    }

    if (!m_envelope->m_rcpt_list.empty())
        m_proto_state = STATE_RCPT_OK;
    else
        m_proto_state = STATE_AFTER_MAIL;


    std::string m_answer;

    if (!m_check_rcpt.m_answer.empty())
        result = m_check_rcpt.m_answer;

    std::ostream response_stream(&m_response);
    response_stream << result;

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

#if ENABLE_AUTH_BLACKBOX
void smtp_connection::handle_bb_result()
{
    if (!m_bb_check_rcpt)
        return;

    m_check_rcpt = m_bb_check_rcpt->check_rcpt();

    if (m_bb_check_rcpt)
        m_bb_check_rcpt->stop();
    m_bb_check_rcpt.reset();

    handle_bb_result_helper();
}
#endif // ENABLE_AUTH_BLACKBOX

void smtp_connection::handle_spf_check(boost::optional<std::string> result, boost::optional<std::string> expl)
{
    m_spf_result = result;
    m_spf_expl = expl;

    spf_check_.reset();
    m_timer_spfdkim.cancel();
    if (m_so_check_pending)
        start_so_avir_checks();
}

void smtp_connection::handle_dkim_check(dkim_check::DKIM_STATUS status, const std::string& identity)
{
    m_dkim_status = status;
    m_dkim_identity = identity;

    dkim_check_.reset();
    m_timer_spfdkim.cancel();
    if (m_smtp_delivery_pending)
        smtp_delivery_start();
}

bool smtp_connection::smtp_mail( const std::string& _cmd, std::ostream &_response )
{
    if ( strncasecmp( _cmd.c_str(), "from:", 5 ) != 0 )
    {
        m_error_count++;

        _response << "501 5.5.4 Syntax: MAIL FROM:<address>\r\n";
        return true;
    }

    if ( m_proto_state == STATE_START )
    {
        m_error_count++;

        _response << "503 5.5.4 Good girl is greeting first.\r\n";
        return true;
    }

    if  (g_config.m_use_auth && !authenticated_)
    {
	m_error_count++;

	_response << "503 5.5.4 Error: send AUTH command first.\r\n";
	return true;
    }

    param_parser::params_map pmap;
    std::string addr;

    param_parser::parse(_cmd.substr(5) , addr, pmap);

    addr = trim(extract_addr(addr));

    if (std::count_if(addr.begin(), addr.end(), is_invalid) > 0)
    {
        m_error_count++;

        _response << "501 5.1.7 Bad address mailbox syntax.\r\n";
        return true;
    }

    if (g_config.m_message_size_limit > 0)
    {
        unsigned int msize = atoi(pmap["size"].c_str());
        if (msize > g_config.m_message_size_limit)
        {
            m_error_count++;

            _response << "552 5.3.4 Message size exceeds fixed limit.\r\n";
            return true;
        }
    }

    m_proto_state = STATE_CHECK_MAILFROM;

#ifdef ENABLE_AUTH_BLACKBOX
    if (authenticated_)
    {
        if (m_bb_check_mailfrom)
            m_bb_check_mailfrom->stop();

	black_box_client_mailfrom::mailfrom_info_t info;

	info.session_id_ = m_session_id;
	info.mailfrom_ = addr;
	info.ip_ = m_connected_ip.to_string();

        m_bb_check_mailfrom.reset( new black_box_client_mailfrom(io_service_, &g_bb_switch));
        m_bb_check_mailfrom->start( info, strand_.wrap(bind(&smtp_connection::handle_bb_mailfrom_result, shared_from_this(), _1, _2)));
    }
    else
    {
	end_mail_from_command(true, false, addr, "");
    }

    black_box_client_mailfrom::mailfrom_result_t res;
#else


    end_mail_from_command(true, false, addr, "");
#endif // ENABLE_AUTH_BLACKBOX

    return true;
}

bool smtp_connection::smtp_data( const std::string& _cmd, std::ostream &_response )
{
    if ( ( m_proto_state != STATE_RCPT_OK ) )
    {
        m_error_count++;

        _response << "503 5.5.4 Bad sequence of commands.\r\n";
        return true;
    }

    if (m_envelope->m_rcpt_list.empty())
    {
        m_error_count++;

        _response << "503 5.5.4 No correct recipients.\r\n";
        return true;
    }

    _response << "354 Enter mail, end with \".\" on a line by itself\r\n";

    m_proto_state = STATE_BLAST_FILE;
    m_timer_value = g_config.m_smtpd_data_timeout;
    m_envelope->orig_message_size_ = 0;

    time_t now;
    time(&now);

    append(str( boost::format("Received: from %1% (%1% [%2%])\r\n\tby %3% (nwsmtp/Yandex) with %4% id %5%;\r\n\t%6%\r\n")
                    % m_remote_host_name % m_connected_ip.to_string() % boost::asio::ip::host_name()
                    % (m_ehlo ? "ESMTP": "SMTP") % m_envelope->m_id % mail_date(now)
                ),
            m_envelope->added_headers_);

    append(str( boost::format("X-Yandex-Front: %1%\r\n")
                % boost::asio::ip::host_name()
                ),
            m_envelope->added_headers_);

    append(str( boost::format("X-Yandex-TimeMark: %1%\r\n")
                    % now
                ),
            m_envelope->added_headers_);

    return true;
}

void smtp_connection::stop()
{

    g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: disconnect from %2%[%3%]") % m_session_id % m_remote_host_name % m_connected_ip.to_string()));

	m_timer.cancel();
	m_resolver.cancel();

    m_proto_state = STATE_START;

    try
    {
        socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        socket().close();
    }
    catch(...)
    {
    }

    if (m_rbl_check)
    {
        m_rbl_check->stop();
        m_rbl_check.reset();
    }

    if (m_so_check)
    {
        m_so_check->stop();
        m_so_check.reset();
    }

    if (m_avir_check)
    {
        m_avir_check->stop();
        m_avir_check.reset();
    }

#if ENABLE_AUTH_BLACKBOX
    if (m_bb_check_rcpt)
    {
        m_bb_check_rcpt->stop();
        m_bb_check_rcpt.reset();
    }
#endif // ENABLE_AUTH_BLACKBOX

    if (m_smtp_client)
    {
        m_smtp_client->stop();
        m_smtp_client.reset();
    }

    for (std::list<envelope::rcpt>::iterator it=m_envelope->m_rcpt_list.begin();
         it != m_envelope->m_rcpt_list.end();
         ++it)
    {
        if (it->gr_check_)
            it->gr_check_->stop();
        if (it->rc_check_)
            it->rc_check_->stop();
    }

    m_connected_ip = boost::asio::ip::address_v4::any();
}

boost::asio::ip::address smtp_connection::remote_address()
{
    return m_connected_ip;
}

void smtp_connection::handle_timer(const boost::system::error_code& _e)
{
    if (!_e)
    {
        std::ostream response_stream(&m_response);
        response_stream << "421 4.4.2 " << boost::asio::ip::host_name() << " Error: timeout exceeded\r\n";

        if ( m_proto_state == STATE_BLAST_FILE )
        {
            g_log.msg(MSG_NORMAL,str(boost::format("%1%-RECV: timeout after DATA (%2% bytes) from %3%[%4%]")
                            % m_session_id % buffers_.size() % m_remote_host_name % m_connected_ip.to_string()
                                     ));
        }
        else
        {
            const char* state_desc = "";
            switch (m_proto_state)
            {
                case STATE_START:
                    state_desc = "CONNECT";
                    break;
                case STATE_AFTER_MAIL:
                    state_desc = "MAIL FROM";
                    break;
                case STATE_RCPT_OK:
                    state_desc = "RCPT TO";
                    break;
                case STATE_HELLO:
                default:
                    state_desc = "HELO";
                    break;
            }
            g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: timeout after %2% from %3%[%4%]") % m_session_id % state_desc % m_remote_host_name % m_connected_ip.to_string()));
        }

        if (ssl_state_ == ssl_active)
		{
            async_say_goodbye(m_ssl_socket, m_response);
		}
		else
		{
    	    boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
		}
    }
}

void smtp_connection::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(
        strand_.wrap(boost::bind(&smtp_connection::handle_timer,
                        shared_from_this(), boost::asio::placeholders::error)));
}

void smtp_connection::end_mail_from_command(bool _start_spf, bool _start_async, std::string _addr, const std::string &_response)
{

    if (_start_spf)
    {
        // start SPF check
        spf_parameters p;
        p.domain = m_helo_host;
        p.from = _addr;
        p.ip = m_connected_ip.to_string();
        m_spf_result.reset();
        m_spf_expl.reset();
        spf_check_.reset(new spf_check);

        spf_check_->start(io_service_, p,
                strand_.wrap(boost::protect(boost::bind(&smtp_connection::handle_spf_check,
                                        shared_from_this(), _1, _2)))
                          );

        m_timer_spfdkim.expires_from_now(boost::posix_time::seconds(g_config.m_spf_timeout));
        m_timer_spfdkim.async_wait(
            strand_.wrap(boost::bind(&smtp_connection::handle_spf_timeout,
                            shared_from_this(), boost::asio::placeholders::error)));
    }

#ifdef ENABLE_AUTH_BLACKBOX
    int karma = m_envelope->karma_;
    int karma_status = m_envelope->karma_status_;
    time_t born_time  = m_envelope->time_stamp_;
    bool auth_mailfrom = m_envelope->auth_mailfrom_;
#endif

    m_envelope.reset(new envelope());

#ifdef ENABLE_AUTH_BLACKBOX
    if (auth_mailfrom && _start_spf)			// setup karma params
    {
		m_envelope->karma_ = karma;
		m_envelope->karma_status_ = karma_status;
		m_envelope->time_stamp_ = born_time;
		m_envelope->auth_mailfrom_ = true;
    }

#endif
    gr_headers_ = greylisting_client::headers();

    m_smtp_from = _addr;

    m_envelope->m_sender = _addr.empty() ? "<>" : _addr;

    g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-RECV: from=<%3%>") % m_session_id % m_envelope->m_id % m_envelope->m_sender));

    std::ostream response_stream(&m_response);

    if (_response.empty())
    {
		m_proto_state = STATE_AFTER_MAIL;
		response_stream << "250 2.1.0 <" <<  _addr << "> ok\r\n";
    }
    else
    {
		response_stream << _response << "\r\n";
    }

    m_message_count++;

    if (_start_async)
    {

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
}
