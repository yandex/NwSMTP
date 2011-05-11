#include <algorithm>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <iostream>
#include "log.h"

#include "smtp_connection_manager.h"

bool smtp_connection_manager::start(smtp_connection_ptr _session, unsigned int _max_sessions_per_ip, unsigned int _max_sessions, std::string &_msg)
{
    boost::mutex::scoped_lock lck(m_mutex);

    if (m_sessions.size() >= _max_sessions)
    {
        _msg = str(boost::format("421 4.7.0 %1% Error: too many connections.\r\n") % boost::asio::ip::host_name());
        return false;
    }

    if (get_ip_session(_session->remote_address()) >= _max_sessions_per_ip)
    {
        _msg = str(boost::format("421 4.7.0 %1% Error: too many connections from %2%\r\n") % boost::asio::ip::host_name() % _session->remote_address().to_string());
        return false;
    }

    m_sessions.insert(_session);
    //  int sess_sz = m_sessions.size();

    ip_inc(_session->remote_address());

    //  lck.unlock();
    //  g_log.msg(MSG_NORMAL, str(boost::format("(start) Connection size:%1%") % sess_sz));

    return true;
}

void smtp_connection_manager::stop(smtp_connection_ptr _session)
{
    boost::mutex::scoped_lock lck(m_mutex);

    std::set<smtp_connection_ptr>::iterator sessit = m_sessions.find(_session);
    if (sessit != m_sessions.end())
    {
        m_sessions.erase(sessit);
        //              int sess_sz = m_sessions.size(); // ###

        ip_dec(_session->remote_address());
        lck.unlock();

        //              g_log.msg(MSG_NORMAL, str(boost::format("(stop) Connection size:%1%") % sess_sz));     // ###
    }
    _session->stop();
}

void smtp_connection_manager::stop_all()
{
    std::for_each(m_sessions.begin(), m_sessions.end(),
            boost::bind(&smtp_connection::stop, _1));

    m_sessions.clear();
}

unsigned int smtp_connection_manager::ip_inc(const boost::asio::ip::address _address)
{
    per_ip_session_t::iterator it = m_ip_count.find(_address.to_v4().to_ulong());

    if (it == m_ip_count.end())
    {
        m_ip_count.insert(per_ip_session_t::value_type(_address.to_v4().to_ulong(), 1));
        return 1;
    }

    (it->second)++;

    return it->second;
}

unsigned int smtp_connection_manager::ip_dec(const boost::asio::ip::address _address)
{
    per_ip_session_t::iterator it = m_ip_count.find(_address.to_v4().to_ulong());

    if (it != m_ip_count.end())
    {
        if (it->second > 0)
        {
            it->second--;
            return it->second;
        }
        else
        {
            m_ip_count.erase(it);
        }
    }

    return 0;
}

unsigned int smtp_connection_manager::get_ip_session(const boost::asio::ip::address _address)
{
    per_ip_session_t::const_iterator it = m_ip_count.find(_address.to_v4().to_ulong());

    if (it == m_ip_count.end())
    {
        return 0;
    }
    else
    {
        return it->second;
    }
}
