#if !defined(_ENVELOPE_H_)
#define _ENVELOPE_H_

#include <sys/types.h>
#include <string>
#include <list>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "buffers.h"
#include "check.h"
#include "timer.h"
#include "coroutine.hpp"

struct envelope
        : public boost::enable_shared_from_this<envelope>,
          private boost::noncopyable

{
    struct rcpt
    {
        std::string m_name;
        
        long long unsigned m_suid;
        std::string m_uid;
    
        std::string m_remote_answer;
        
        check::chk_status m_delivery_status;
        
        unsigned int m_spam_status;
        
        bool operator == (struct rcpt &_rcpt)
        {
            return m_name == _rcpt.m_name;
        }

        rcpt() 
                : m_suid(0),
                  m_delivery_status(check::CHK_TEMPFAIL),
                  m_spam_status(0)
        {}
    };

    typedef std::list<rcpt> rcpt_list_t;

    envelope();

    mutable_buffers::iterator header_beg_;
    mutable_buffers::iterator body_beg_;
    mutable_buffers::iterator body_end_;

    std::list< std::string > added_headers_;

    std::list< boost::asio::const_buffer > altered_message_;
    std::list< boost::asio::const_buffer > orig_message_;
    std::size_t orig_message_size_;
        
    void add_recipient(const std::string &_rcpt, long long unsigned _suid, const std::string& _uid);

    bool has_recipient(long long unsigned suid);
    
    void set_personal_spam_status(long long unsigned _suid, unsigned int _status);
    
    void remove_delivered_rcpt();
        
    static std::string generate_new_id();
    
    static check::chk_status smtp_code_decode(unsigned int code);
    
    void cleanup_answers();
    
    std::string m_id;
        
    std::string m_sender;
    
    rcpt_list_t m_rcpt_list;
        
    bool m_spam;                        // envelope is spam
    
    bool m_no_local_relay;              // no local relay if we have one or more aliases
    
    timer m_timer;

    coroutine smtp_delivery_coro_;   
};



typedef boost::shared_ptr<envelope> envelope_ptr;

#endif
