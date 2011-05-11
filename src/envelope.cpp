#include <stdio.h>

#include "envelope.h"

envelope::envelope()
        : added_headers_(),
          orig_headers_(),
          altered_message_(),
          orig_message_(),
          orig_message_token_marker_size_(0),
          orig_message_body_beg_(),
          orig_message_size_(0),
          m_id(generate_new_id()),
          m_sender(),
          m_rcpt_list(),
          m_spam(false),
          m_no_local_relay(false),
          m_timer(),
          smtp_delivery_coro_()
#ifdef ENABLE_AUTH_BLACKBOX
	,karma_(0),
	karma_status_(0),
	time_stamp_(0),
	auth_mailfrom_(false)
#endif

{
}

struct rcpt_compare
{
    long long unsigned m_suid;
    rcpt_compare(long long unsigned suid): m_suid(suid)
    {
    }

    bool operator () (const envelope::rcpt &_rcpt)
    {
        return _rcpt.m_suid == m_suid;
    }
};

bool envelope::has_recipient(long long unsigned suid)
{
    return m_rcpt_list.end() !=
            std::find_if(m_rcpt_list.begin(), m_rcpt_list.end(), rcpt_compare(suid));
}

envelope::rcpt_list_t::iterator envelope::add_recipient(const std::string &_rcpt,
        long long unsigned _suid, const std::string& _uid)
{
    if (!_suid || !has_recipient(_suid))
    {
        envelope::rcpt rcpt;

        rcpt.m_name = _rcpt;

        rcpt.m_suid = _suid;

        rcpt.m_uid = _uid;

        rcpt.m_spam_status = 0;

        m_rcpt_list.push_back(rcpt);

        return --m_rcpt_list.end();
    }
    return m_rcpt_list.end();
}

static char code_table[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx";

std::string envelope::generate_new_id()
{

    std::string res;
    time_t now;

    struct tm *lt;

    int pid = getpid();
    unsigned long tid = (unsigned long)pthread_self();

    time( &now );
    lt = localtime( &now );

    res += code_table[ lt->tm_min ];
    res += code_table[ lt->tm_sec ];
    res += code_table[ pid % 60 ];
    res += code_table[ tid % 60 ];
    res += code_table[ rand() % 60 ];
    res += code_table[ rand() % 60 ];
    res += code_table[ rand() % 60 ];
    res += code_table[ rand() % 60 ];

    return res;
}

static bool pred(const envelope::rcpt_list_t::value_type &_t)
{
    return _t.m_delivery_status == check::CHK_ACCEPT;
}

void envelope::remove_delivered_rcpt()
{
    m_rcpt_list.erase(std::remove_if(m_rcpt_list.begin(), m_rcpt_list.end(), pred), m_rcpt_list.end());
}

struct find_rcpt
{
    find_rcpt(long long unsigned _suid)
    {
        m_suid = _suid;
    };

    bool operator () (const envelope::rcpt_list_t::value_type &_rcpt)
    {
        return m_suid == _rcpt.m_suid;
    };

  protected:

    long long unsigned m_suid;
};

void envelope::set_personal_spam_status(long long unsigned _suid, unsigned int _status)
{
    rcpt_list_t::iterator it = find_if(m_rcpt_list.begin(), m_rcpt_list.end(), find_rcpt(_suid));

    if (it != m_rcpt_list.end())
    {
        it->m_spam_status = _status;

        return;
    }
}

check::chk_status envelope::smtp_code_decode(unsigned int code)
{
    if ((code >= 200) && (code < 300))
    {
        return check::CHK_ACCEPT;
    }
    else if ((code >= 400) && (code < 500))
    {
        return check::CHK_TEMPFAIL;
    }
    else if ((code >= 500) && (code < 600))
    {
        return check::CHK_REJECT;
    }

    return check::CHK_TEMPFAIL;                 // Invalid
}

void envelope::cleanup_answers()
{
    for(rcpt_list_t::iterator it = m_rcpt_list.begin(); it !=  m_rcpt_list.end(); it++)
    {
        it->m_remote_answer.clear();
    }
}


