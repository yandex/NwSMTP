#if !defined(_SMTP_CONNECTION_MANAGER_H_)
#define _SMTP_CONNECTION_MANAGER_H_

#include <set>
#include <boost/thread.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>

#include "smtp_connection.h"

class smtp_connection_manager
        : private boost::noncopyable
{
  public:

    bool start(smtp_connection_ptr _session, unsigned int _max_sessions_per_ip, unsigned int _max_sessions, std::string &_msg);

    void stop(smtp_connection_ptr _session);

    void stop_all();

  protected:

    std::set<smtp_connection_ptr> m_sessions;

    typedef boost::unordered_map < unsigned long, unsigned int> per_ip_session_t;

    per_ip_session_t m_ip_count;

    unsigned int ip_inc(const boost::asio::ip::address _address);
    unsigned int ip_dec(const boost::asio::ip::address _address);
    unsigned int get_ip_session(const boost::asio::ip::address _address);

    boost::mutex m_mutex;
};

#endif // _SMTP_CONNECTION_MANAGER_H_
