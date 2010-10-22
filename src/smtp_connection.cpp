#include <vector>
#include <boost/bind.hpp>
#include <sstream> 
#include <iostream>
#include <fstream>
#include <boost/type_traits.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <algorithm>

#include "smtp_connection.h"
#include "smtp_connection_manager.h"
#include "log.h"
#include "options.h"
#include "uti.h"
#include "rfc_date.h"
#include "aliases.h"
#include "param_parser.h"
#include "header_parser.h"
#include "rfc822date.h"
#include "aspf.h"
#include "ip_options.h"

using namespace y::net;

smtp_connection::smtp_connection(boost::asio::io_service &_io_service, smtp_connection_manager &_manager, boost::asio::ssl::context& _context)
        : io_service_(_io_service),
          m_ssl_socket(_io_service, _context),
          m_manager(_manager),
          m_connected_ip(boost::asio::ip::address_v4::any()),
          m_resolver(_io_service),
          m_smtp_delivery_pending(false),
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

boost::asio::ip::tcp::socket& smtp_connection::socket()
{
    return m_ssl_socket.next_layer();
}

void smtp_connection::start()
{
    #if defined(HAVE_PA_INTERFACE_H)
    m_pa_timer.start();
    #endif
    
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
    
    ssl_state_ = ssl_none;

    add_new_command("rcpt", &smtp_connection::smtp_rcpt);
    add_new_command("mail", &smtp_connection::smtp_mail);
    add_new_command("data", &smtp_connection::smtp_data);
    add_new_command("ehlo", &smtp_connection::smtp_ehlo);
    add_new_command("helo", &smtp_connection::smtp_helo);
    add_new_command("quit", &smtp_connection::smtp_quit);
    add_new_command("rset", &smtp_connection::smtp_rset);
    add_new_command("noop", &smtp_connection::smtp_noop);

    if (g_config.m_use_tls)
    {
        add_new_command("starttls", &smtp_connection::smtp_starttls);
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
    
    marker1_ =  marker2_ = marker3_ = buffers_.begin();
   
    if (m_rbl_check && m_rbl_check->get_status(rbl_status))
    {    
        if (m_rbl_check)
            m_rbl_check->stop();

        m_rbl_check.reset(new rbl_check(io_service_));
        
        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: reject: CONNECT from %2%[%3%]: %4%; proto=SMTP") 
                        % m_session_id % m_remote_host_name % m_connected_ip.to_v4().to_string() % rbl_status));
        
        response_stream << rbl_status;
        
        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    
    }
    else if (m_manager.start(shared_from_this(), g_config.m_client_connection_count_limit, g_config.m_connection_count_limit, error))
    {
        response_stream << "220 " << boost::asio::ip::host_name() << " " << (g_config.m_smtp_banner.empty() ? "Ok" : g_config.m_smtp_banner) << "\r\n";
        
        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, 
                                shared_from_this(), boost::asio::placeholders::error)));
    }
    else
    {
        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: reject: CONNECT from %2%[%3%]: %4%; proto=SMTP") 
                        % m_session_id % m_remote_host_name % m_connected_ip.to_v4().to_string()  % error));
    
        response_stream << error;
        
        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
        
    }
}

void smtp_connection::start_read()
{

    if ((m_proto_state == STATE_CHECK_RCPT) || (m_proto_state == STATE_CHECK_DATA) || (m_proto_state == STATE_CHECK_AUTH))
    {
        m_timer.cancel();               // wait for check to complete
        return;
    }    

    mutable_buffers::iterator::difference_type unseen_size = marker3_ - marker2_;
    
    restart_timeout();
    
    if (unseen_size > 0)
    {   
        handle_read(boost::system::error_code(), unseen_size);
    } 
    else
    { 
        if (!m_read_pending_)
        {
            if (ssl_state_ == ssl_active)
            {
                m_ssl_socket.async_read_some(tail_buffer(),     
                        strand_.wrap(boost::bind(&smtp_connection::handle_read, shared_from_this(),
                                        boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
            }
            else
            {
                socket().async_read_some(tail_buffer(),         
                        strand_.wrap(boost::bind(&smtp_connection::handle_read, shared_from_this(),
                                        boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
            }
                    
            m_read_pending_ = true;
        }
    }
    
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
        mutable_buffers::iterator& it = marker2_;
        mutable_buffers::iterator e =  it + size;
        mutable_buffers::iterator b = it;
        marker3_ = e;

        if (m_proto_state == STATE_BLAST_FILE)
        {
            const char* tail = 0;
            const char* eom  = 0;
            bool eom_found = eom_parser_.parse(b.ptr(), b.ptr()+size, eom, tail);
            ptrdiff_t mchars_parsed = eom - b.ptr(); // run of chars belonging to the current message in the block read

            if (mchars_parsed)
                marker1_ = b + mchars_parsed;
            it = e;
            
            if (eom_found)
            {
                assert(*marker1_ == '.');
                m_envelope->body_end_ = marker1_;
                it = b + (tail - b.ptr());  // pretend we read up to the beginning of data following the message
                marker1_ = it;
                m_envelope->orig_message_ = mutable_buffers::const_buffers( m_envelope->header_beg_, m_envelope->body_end_ );
                m_envelope->orig_message_size_ = m_envelope->body_end_ - m_envelope->header_beg_;

                m_proto_state = STATE_CHECK_DATA;       
                io_service_.post(strand_.wrap(bind(&smtp_connection::start_check_data, shared_from_this())));
                return;
            }
        }
        else 
        {
            for ( ; it != e ; ++it)
            {
                if (*it == '\n')
                {
                    if (it != marker1_)
                    {
                        std::string command (marker1_, it);
                        marker1_ = ++it;                        

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
                                boost::asio::async_write(m_ssl_socket, m_response,
                                        strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                                        boost::asio::placeholders::error)));
                            }
                            else
                            {
                                boost::asio::async_write(socket(), m_response,
                                        strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                                        boost::asio::placeholders::error)));
                            }       
                        }               
                        
                        release_unused_buffers();
                        
                        return;
                    }
                }
            }
            
            release_unused_buffers();       
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
    else if (g_config.m_rc_check && !rc_checks_.empty())
    {   
        m_check_data.m_rc_puts_pending = 0;
        for (std::list< rc_check_ptr >::iterator it=rc_checks_.begin(); it!=rc_checks_.end(); ++it)
        {         
            m_check_data.m_rc_puts_pending++;
            (*it)->put(strand_.wrap(
                boost::bind(&smtp_connection::handle_rc_put, 
                        shared_from_this(), _1, _2, *it)), 
                    m_envelope->orig_message_size_
                       );           
        }
    }    
    else if (g_config.m_so_check && m_envelope->orig_message_size_ > 0)
    {
        if (m_so_check)
            m_so_check->stop();
        
        m_so_check.reset(new so_client(io_service_, &g_so_switch));     
        m_so_check->start(m_check_data, bind(&smtp_connection::handle_so_check, 
                        shared_from_this()), m_envelope);
    }
    else
    {
        if (m_so_check)
            m_so_check->stop(); 
        m_so_check.reset();
        
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
    
    if (m_smtp_delivery_pending)
    {
        smtp_delivery_start();
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
        const boost::unordered_set<string>& rem_h)
{
    string lname; // lower-cased header name
    size_t name_sz = name.size();
    lname.reserve(name_sz);
    std::transform(name.begin(), name.end(), back_inserter(lname), ::tolower);
    unique_h.insert( lname );

    if ( !strcmp(lname.c_str(), "message-id") )
        message_id = value;

    // add a header field to the list only if we don't have to remove it from the message
    if (!g_config.m_remove_headers || rem_h.find(lname) == rem_h.end())
        h.push_back( header );  
}
}
  
void smtp_connection::smtp_delivery_start()
{
    if (spf_check_ && spf_check_->is_inprogress())  // wait for SPF check to complete
    {
        m_smtp_delivery_pending = true;
        return;
    }

    if (dkim_check_ && dkim_check_->is_inprogress()) // wait for DKIM check to complete
    {
        m_smtp_delivery_pending = true;
        return;
    }
    m_smtp_delivery_pending = false;

    bool continue_delivery = false;    
    bool has_dkim_headers = false;    

    reenter (m_envelope->smtp_delivery_coro_) 
    {
        for (;;)
        {
            if (m_check_data.m_result == check::CHK_ACCEPT)
            {
                // alter headers & compose the resulting message here
                typedef list<header_iterator_range_t> hl_t; // header fields subset from the original message for the composed message
                hl_t h;
                header_iterator_range_t message_id;
                boost::unordered_set<std::string> unique_h;
                header_iterator_range_t::iterator b = m_envelope->header_beg_;
                header_iterator_range_t::iterator e = m_envelope->body_end_;
                header_iterator_range_t r (b, e);
                header_iterator_range_t::iterator bs = parse_header(r,
                        boost::bind(&handle_parse_header, _1, _2, _3, 
                                boost::ref(h), boost::ref(message_id), boost::ref(unique_h), 
                                boost::cref(g_config.m_remove_headers_set)));
                m_envelope->body_beg_ = bs;

                m_envelope->altered_message_ = mutable_buffers::const_buffers( bs, e );
                m_envelope->altered_message_.push_front( boost::asio::const_buffer( "\r\n", 2 ) );

                for (hl_t::const_reverse_iterator it=h.rbegin(); it!=h.rend(); ++it)
                {
                    // append existing headers
                    std::list< boost::asio::const_buffer > h = mutable_buffers::const_buffers( it->begin(), it->end() );
                    h.push_back( boost::asio::const_buffer( "\r\n", 2 ) );
                    m_envelope->altered_message_.insert( m_envelope->altered_message_.begin(), h.begin(), h.end() );
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

                    m_envelope->added_headers_.push_back( str( boost::format("Message-Id: %1%\r\n") % message_id_str ));

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
                    time ( &rawtime );
                    m_envelope->added_headers_.push_back(
                        str( boost::format("Date: %1%")
                                % rfc822date(&rawtime, timestr, sizeof timestr, zonestr, sizeof zonestr)
                             )
                        );          
                }
                if ( unique_h.find("from") == unique_h.end() )
                {
                    m_envelope->added_headers_.push_back(
                        std::string("From: MAILER-DAEMON\r\n")
                        );
                }
                if ( unique_h.find("to") == unique_h.end() )
                {
                    m_envelope->added_headers_.push_back(
                        std::string("To: undisclosed-recipients:;\r\n")
                        );          
                }

                has_dkim_headers = unique_h.find("dkim-signature") != unique_h.end();

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
            if (has_dkim_headers)
            {
                dkim_check_.reset( new dkim_check);
                m_smtp_delivery_pending = true;

                m_timer_spfdkim.expires_from_now(boost::posix_time::seconds(g_config.m_dkim_timeout));
                m_timer_spfdkim.async_wait(
                    strand_.wrap(boost::bind(&smtp_connection::handle_dkim_timeout, 
                                    shared_from_this(), boost::asio::placeholders::error)));

                m_dkim_status = dkim_check::DKIM_NONE;
                m_dkim_identity.clear();
                yield dkim_check_->start(
                    strand_.get_io_service(),
                    dkim_parameters(m_envelope->header_beg_, m_envelope->body_beg_, m_envelope->body_end_),
                    strand_.wrap(
                        boost::bind(&smtp_connection::handle_dkim_check, 
                                shared_from_this(), _1, _2))
                    );

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

                m_envelope->added_headers_.push_back(ah);
                g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%") % m_session_id % ah));
            }       

            for (std::list<std::string>::const_reverse_iterator it = m_envelope->added_headers_.rbegin(); 
                 it != m_envelope->added_headers_.rend();
                 ++it)
            {
                // append new headers
                m_envelope->altered_message_.push_front( boost::asio::const_buffer( it->c_str(), it->size() ) );
            }

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

    #if defined(HAVE_PA_INTERFACE_H)
    pa::wmi_profiler::add(pa::smtp_client, m_remote_host_name, "smtp_client_session", m_session_id + "-" + m_envelope->m_id, m_pa_timer.stop()); 
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
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, this,
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
    rc_checks_.clear();
  
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

    if (g_config.m_use_tls)
    {
        esmtp_flags += "250-STARTTLS\r\n";
    }

#if ENABLE_AUTH_BLACKBOX
    if (g_config.m_use_auth)
    {
        esmtp_flags += "250-AUTH PLAIN\r\n";
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

static std::string trim(const std::string &_str)
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

        _response << "503 5.5.4 Bad sequence of command.\r\n";
        return true;
    }
        
    if ( strncasecmp( _cmd.c_str(), "to:", 3 ) != 0 )
    {
        m_error_count++;

        _response << "501 5.5.4 Wrong param.\r\n";
        return true;
    }
        
    if (m_rcpt_count >= m_max_rcpt_count)
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
                    m_rcpt_count++;             
                    m_envelope->m_no_local_relay |= g_aliases.process(m_check_rcpt.m_rcpt, 
                            m_check_rcpt.m_suid,  boost::bind(&envelope::add_recipient, m_envelope, _1, _2, m_check_rcpt.m_uid));
                }
                else
                {
                    // perform rate_control GET check           
                    rc_check_ptr q (new rc_check(io_service_, 
                                    m_check_rcpt.m_rcpt, m_check_rcpt.m_uid, g_config.m_rc_host_list, g_config.m_rc_timeout));
                    rc_checks_.push_back(q);
                    q->get(strand_.wrap(boost::bind(&smtp_connection::handle_rc_get, shared_from_this(), _1, _2, q)));
                    return;
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

    if (m_rcpt_count > 0)
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

void smtp_connection::handle_rc_put(const boost::system::error_code& ec, boost::optional<rc_result> rc, boost::weak_ptr<rc_check> qq)
{
    if (qq.expired()) 
    {
        --m_check_data.m_rc_puts_pending;
        return;
    }

    rc_check_ptr q = qq.lock();

    if (!rc || rc->ok)
    {
        if (!rc && ec != boost::asio::error::operation_aborted) 
        {
            g_log.msg(MSG_NORMAL, str(boost::format("%1%-RC-DATA failed to "
                                    "commit iprate PUT check because of the server"
                                    " being down or bad config; ignored (host=[%2%], rcpt=[%3%])") % 
                            m_session_id % q->get_hostname() % q->get_email()));
        }

        if (--m_check_data.m_rc_puts_pending == 0)
        {           
            m_check_data.m_result = check::CHK_ACCEPT;
            if (g_config.m_so_check && m_envelope->orig_message_size_ > 0)
            {
                m_so_check.reset(new so_client(io_service_, &g_so_switch));     
                m_so_check->start(m_check_data, bind(&smtp_connection::handle_so_check, shared_from_this()), m_envelope);
            }
            else
            {
                avir_check_data();
            }
        }               
    }
    else
    {
        m_check_data.m_rc_puts_pending = 0;
        m_error_count++;
                        
        const rc_parameters& p = q->get_parameters();
        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RC-DATA "
                                "the recipient has exceeded their message rate"
                                " limit (from=%2%,rcpt=<%3%>,uid=%4%,host=[%5%])") %
                        m_session_id % m_smtp_from % q->get_email() % p.ukey % q->get_hostname()));
  
        m_check_data.m_answer = str(boost::format("451 4.5.1 The "
                        "recipient <%1%> has exceeded their message rate "
                        "limit. Try again later.") % q->get_email());
        m_check_data.m_result = check::CHK_TEMPFAIL;
        end_check_data();       
    }

}

void smtp_connection::handle_rc_get(const boost::system::error_code& ec, boost::optional<rc_result> rc, boost::weak_ptr<rc_check> qq)
{
    if (ec == boost::asio::error::operation_aborted || qq.expired())
        return;

    rc_check_ptr q = qq.lock();

    if (m_rcpt_count > 0)
        m_proto_state = STATE_RCPT_OK;
    else
        m_proto_state = STATE_AFTER_MAIL;

    if (!rc && ec != boost::asio::error::operation_aborted)
    {
        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RC-RCPT failed to "
                                "commit iprate check in GET because of the server"
                                " being down or bad config; ignored (host=[%2%], rcpt=[%3%])") % 
                        m_session_id % q->get_hostname() % m_check_rcpt.m_rcpt));
    }
    else if (!rc->ok)
    {
        m_error_count++;                        

        const rc_parameters& p = q->get_parameters();
        g_log.msg(MSG_NORMAL, str(boost::format("%1%-RC-RCPT "
                                "the recipient has exceeded their message rate"
                                " limit (from=%2%,rcpt=<%3%>,uid=%4%,host=[%5%])") %
                        m_session_id % m_smtp_from % m_check_rcpt.m_rcpt % p.ukey % q->get_hostname()));

        std::string result = str(boost::format("451 4.5.1 The "
                        "recipient <%1%> has exceeded their message rate "
                        "limit. Try again later.") % m_check_rcpt.m_rcpt);
        
        std::ostream response_stream(&m_response);              
        response_stream << result;
    
        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));                  
        return;
    }

    // Add this recipient
    m_proto_state = STATE_RCPT_OK;
    m_rcpt_count++;
    m_envelope->m_no_local_relay |= g_aliases.process(m_check_rcpt.m_rcpt, 
            m_check_rcpt.m_suid,  boost::bind(&envelope::add_recipient, m_envelope, 
                    _1, _2, m_check_rcpt.m_uid));

    std::string result = str(boost::format("250 2.1.5 <%1%> recipient ok\r\n") % m_check_rcpt.m_rcpt);
    std::ostream response_stream(&m_response);  
        
    response_stream << result;
    
    boost::asio::async_write(socket(), m_response,
            strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                            boost::asio::placeholders::error)));                      
}

void smtp_connection::handle_spf_check(boost::optional<std::string> result, boost::optional<std::string> expl)
{
    m_spf_result = result;
    m_spf_expl = expl;

    spf_check_.reset();
    m_timer_spfdkim.cancel();
    if (m_smtp_delivery_pending)
        smtp_delivery_start();
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
    if ( m_proto_state != STATE_HELLO )
    {
        m_error_count++;

        _response << "503 5.5.4 Bad sequence of command.\r\n";
        return true;
    }

    if ( strncasecmp( _cmd.c_str(), "from:", 5 ) != 0 )
    {
        m_error_count++;

        _response << "501 5.5.4 Syntax: MAIL FROM:<address>\r\n";
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

    // start SPF check
    spf_parameters p;
    p.domain = m_helo_host;
    p.from = addr;
    p.ip = m_connected_ip.to_string();
    m_spf_result.reset();
    m_spf_expl.reset();
    spf_check_.reset(new spf_check);
    
    spf_check_->start(io_service_, p, strand_.wrap(boost::protect(boost::bind(&smtp_connection::handle_spf_check, 
                                    shared_from_this(), _1, _2)))
                      ); 
                      

    m_timer_spfdkim.expires_from_now(boost::posix_time::seconds(g_config.m_spf_timeout));
    m_timer_spfdkim.async_wait(
        strand_.wrap(boost::bind(&smtp_connection::handle_spf_timeout, 
                        shared_from_this(), boost::asio::placeholders::error)));

    m_envelope.reset(new envelope());
        
    rc_checks_.clear();
        
    m_smtp_from = addr;
    m_envelope->m_sender = addr.empty() ? "<>" : addr;
        
    g_log.msg(MSG_NORMAL, str(boost::format("%1%-%2%-RECV: from=<%3%>") % m_session_id % m_envelope->m_id % m_envelope->m_sender));
        
    _response << "250 2.1.0 <" <<  addr << "> ok\r\n";
        
    m_rcpt_count = 0;

    m_proto_state = STATE_AFTER_MAIL;
        
    m_message_count++;

    return true;
}

bool smtp_connection::smtp_data( const std::string& _cmd, std::ostream &_response )
{
    if ( ( m_proto_state != STATE_RCPT_OK ) )
    {
        m_error_count++;

        _response << "503 5.5.4 Bad sequence of command.\r\n";
        return true;
    }
    
    if (m_rcpt_count == 0)
    {
        m_error_count++;

        _response << "503 5.5.4 No correct recipients.\r\n";
        return true;
    }
    
    _response << "354 Enter mail, end with \".\" on a line by itself\r\n";

    m_proto_state = STATE_BLAST_FILE;
    m_timer_value = g_config.m_smtpd_data_timeout;

    release_unused_buffers();
    m_envelope->header_beg_ = marker1_;
    
    time_t now;    
    time(&now);    

    m_envelope->added_headers_.push_back( 
        str( boost::format("Received: from %1% (%1% [%2%])\r\n\tby %3% (nwsmtp/Yandex) with %4% id %5%;\r\n\t%6%\r\n")
                % m_remote_host_name % m_connected_ip.to_string() % boost::asio::ip::host_name()
                % (m_ehlo ? "ESMTP": "SMTP") % m_envelope->m_id % mail_date(now)
             )
        );

    m_envelope->added_headers_.push_back( 
        str( boost::format("X-Yandex-Front: %1%\r\n")
                % boost::asio::ip::host_name()                       
             )
        );

    m_envelope->added_headers_.push_back( 
        str( boost::format("X-Yandex-TimeMark: %1%\r\n")
                % now                
             )
        );
      
    return true;
}

void smtp_connection::stop()
{
    g_log.msg(MSG_NORMAL, str(boost::format("%1%-RECV: disconnect from %2%[%3%]") % m_session_id % m_remote_host_name % m_connected_ip.to_string()));

    m_resolver.cancel();
    m_timer.cancel();
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
    
    for (std::list<rc_check_ptr >::iterator it=rc_checks_.begin(); it!=rc_checks_.end(); ++it)    
        (*it)->stop();

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
            std::size_t sz =  marker3_ - buffers_.begin();
            
            g_log.msg(MSG_NORMAL,str(boost::format("%1%-RECV: timeout after DATA (%2% bytes) from %3%[%4%]") 
                            % m_session_id % sz % m_remote_host_name % m_connected_ip.to_string()
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

        boost::asio::async_write(socket(), m_response,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
        m_manager.stop(shared_from_this());
    }   
}
                    
void smtp_connection::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(
        strand_.wrap(boost::bind(&smtp_connection::handle_timer, 
                        shared_from_this(), boost::asio::placeholders::error)));
}

void smtp_connection::release_unused_buffers()
{
    mutable_buffers::iterator e = buffers_.end();
    bool m1e = (marker1_ == e);
    bool m2e = (marker2_ == e);
    bool m3e = (marker3_ == e);
    buffers_.release_head(marker1_);
    if (m1e)
    {
        assert(m3e);
        assert(m2e);
        marker1_ = marker2_ = marker3_ = buffers_.begin();
    }   
}

boost::asio::mutable_buffers_1 smtp_connection::tail_buffer()
{
    mutable_buffers::iterator e = buffers_.end();
    bool m1e = (marker1_ == e);
    bool m2e = (marker2_ == e);
    bool m3e = (marker3_ == e);
    boost::asio::mutable_buffers_1 b = buffers_.tail(marker3_);
    if (m3e && m2e)
        marker2_ = marker3_;
    if (m3e && m1e)
        marker1_ = marker3_;                   
    return b;
}
