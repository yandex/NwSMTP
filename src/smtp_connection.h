#ifndef _SMTP_CONNECTION_H_
#define _SMTP_CONNECTION_H_

#include <config.h>
#include <boost/unordered_map.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/range/iterator_range.hpp>
#include <net/dns_resolver.hpp>
#include <boost/optional.hpp>

#if defined(HAVE_CONFIG_H)
#include "../config.h"
#endif
#if defined(HAVE_PA_INTERFACE_H)
#include <pa/interface.h>
#endif

#include "envelope.h"
#include "buffers.h"
#include "rbl.h"

#ifdef ENABLE_AUTH_BLACKBOX
#include "bb_client_rcpt.h"
#include "bb_client_auth.h"
#endif // ENABLE_AUTH_BLACKBOX

#include "so_client.h"
#include "avir_client.h"
#include "smtp_client.h"
#include "rc_check.h"
#include "eom_parser.h"
#include "atormoz.h"
#include "adkim.h"
#include "yield.hpp"
#include "auth.h"


class smtp_connection_manager;

class smtp_connection
        : public boost::enable_shared_from_this<smtp_connection>,
          private boost::noncopyable
{
  public:

    explicit smtp_connection(boost::asio::io_service &_io_service, smtp_connection_manager &_manager, boost::asio::ssl::context& _context);
    
    ~smtp_connection();
    
    boost::asio::ip::tcp::socket& socket();
  
    void start();
    void stop();
    
    boost::asio::ip::address remote_address();
    
  protected:

    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_t;
        
    void handle_write_request(const boost::system::error_code& err);
    void handle_ssl_handshake(const boost::system::error_code& err);
    void handle_last_write_request(const boost::system::error_code& err);
    
    void handle_read(const boost::system::error_code& _err, std::size_t _size);
    void start_read();
    
    boost::asio::io_service &io_service_;
    ssl_socket_t m_ssl_socket;
    
    boost::asio::streambuf m_response;
    
    //---     
    
    typedef boost::function< bool (smtp_connection*, const std::string&, std::ostream&) > proto_func_t;
    typedef boost::unordered_map < std::string, proto_func_t> proto_map_t;
        
    proto_map_t m_proto_map;
    
    void add_new_command(const char *_command, proto_func_t _func);
    
    bool execute_command(const std::string &_cmd, std::ostream &_response);

    //---
    bool smtp_quit( const std::string& _cmd, std::ostream &_response);
    bool smtp_noop ( const std::string& _cmd, std::ostream &_response);
    bool smtp_rset ( const std::string& _cmd, std::ostream &_response);
    bool smtp_ehlo ( const std::string& _cmd, std::ostream &_response);
    bool smtp_helo ( const std::string& _cmd, std::ostream &_response);
    bool smtp_mail ( const std::string& _cmd, std::ostream &_response);
    bool smtp_rcpt ( const std::string& _cmd, std::ostream &_response);
    bool smtp_data ( const std::string& _cmd, std::ostream &_response);
    
    bool smtp_starttls ( const std::string& _cmd, std::ostream &_response);
    
    bool smtp_auth ( const std::string& _cmd, std::ostream &_response);
    bool continue_smtp_auth ( const std::string& _cmd, std::ostream &_response );
    
    //---
    typedef enum {
        STATE_START = 0,
        STATE_HELLO,
        STATE_AFTER_MAIL,
        STATE_RCPT_OK,
        STATE_BLAST_FILE,
        STATE_CHECK_RCPT,
        STATE_CHECK_DATA,
        STATE_CHECK_AUTH,
        STATE_AUTH_MORE,
    } proto_state_t;
                
    proto_state_t m_proto_state;                
    
    typedef enum {
        ssl_none = 0,
        ssl_hand_shake,
        ssl_active
    } ssl_state_t;
                    
    ssl_state_t ssl_state_;                 
    
    //---
    bool hello( const std::string &_host);
    
    bool m_ehlo;
    std::string m_remote_host_name;
    std::string m_helo_host;
    
    //---
    unsigned int m_rcpt_count;
    unsigned int m_message_count; 

    //---    
    smtp_connection_manager& m_manager;
    
    boost::asio::ip::address m_connected_ip;

    //---
    y::net::dns::resolver m_resolver;
    
    void handle_back_resolve(const boost::system::error_code& ec, y::net::dns::resolver::iterator it);
    void start_proto();

    // SPF

    string m_smtp_from;
    bool m_smtp_delivery_pending;
    boost::optional<std::string> m_spf_result;
    boost::optional<std::string> m_spf_expl;
    void handle_spf_check(boost::optional<std::string> result, boost::optional<std::string> expl);
    void handle_spf_timeout(const boost::system::error_code& ec);
    boost::shared_ptr<class spf_check> spf_check_;

    // DKIM
    typedef boost::shared_ptr<dkim_check> dkim_check_ptr;
    dkim_check_ptr dkim_check_;
    dkim_check::DKIM_STATUS m_dkim_status;
    std::string m_dkim_identity;
    void handle_dkim_check(dkim_check::DKIM_STATUS status, const std::string& identity);
    void handle_dkim_timeout(const boost::system::error_code& ec);

    // RC

    typedef boost::shared_ptr<rc_check> rc_check_ptr;    
    std::list< rc_check_ptr > rc_checks_;
    void handle_rc_get(const boost::system::error_code& ec, boost::optional<rc_result> rc, boost::weak_ptr<rc_check>);
    void handle_rc_put(const boost::system::error_code& ec, boost::optional<rc_result> rc, boost::weak_ptr<rc_check>);
    
    boost::asio::io_service::strand strand_;

    //---
    
    rbl_client_ptr m_rbl_check;
    
    //--
    check_rcpt_t m_check_rcpt;

#ifdef ENABLE_AUTH_BLACKBOX    
    black_box_client_rcpt_ptr m_bb_check_rcpt;
    black_box_client_auth_ptr m_bb_check_auth;    

    void handle_bb_result();

    void start_passport_auth(const black_box_client_auth::auth_info_t &_info);
    
    void handle_bb_auth_result(check::chk_status _check);
    void handle_bb_auth_result_helper(check::chk_status _check);
#endif // ENABLE_AUTH_BLACKBOX
    
    void handle_bb_result_helper();

    //---
    
    so_client_ptr m_so_check;
    
    avir_client_ptr m_avir_check;
    
    smtp_client_ptr m_smtp_client;
    
    check_data_t m_check_data;
    
    void start_check_data();
    void avir_check_data();
    void handle_so_check();
    void handle_avir_check();
    void smtp_delivery_start();
    void end_check_data();
    void end_lmtp_proto();
    void smtp_delivery();
    
    //---
    
    envelope_ptr m_envelope;

    mutable_buffers buffers_;
    boost::mutex buffers_mutex_;

    // parser markers
    mutable_buffers::iterator marker1_; // points past the end of last parsed command / message part in buffer list
    mutable_buffers::iterator marker2_; // points past the last read character of input in buffer list
    mutable_buffers::iterator marker3_; // points past the end of input in buffer list
    
    
    eom_parser eom_parser_;

    boost::asio::mutable_buffers_1 tail_buffer();
    void release_unused_buffers();
    //    boost::iterator_range<mutable_buffers::iterator> tail_range(std::size_t atleast);
   
    std::string m_session_id;
    
    // ---
    
    boost::asio::deadline_timer m_timer;

    boost::asio::deadline_timer m_timer_spfdkim;
    
    unsigned int m_timer_value;
             
    void handle_timer( const boost::system::error_code &_error);
                                             
    void restart_timeout();
    
    void cancel_timer();    
    
    unsigned int m_max_rcpt_count;

    bool m_read_pending_;

    int m_error_count;
    
    #if defined(HAVE_PA_INTERFACE_H)
    pa::stimer_t m_pa_timer;    
    #endif
    
    auth auth_;
    
    bool authenticated_;
};

typedef boost::shared_ptr<smtp_connection> smtp_connection_ptr;

#endif // _SMTP_CONNECTION_H_
