#include <iostream>
#include "log.h"

logger g_log;


logger::logger()
        :  m_exit(false),
           m_log_prio(0)
{
}

void logger::initlog(const std::string &_info, int _log_prio)
{
    openlog("nwsmtp", 0, LOG_MAIL);
    m_log_prio = _log_prio;

}

void logger::msg(int _prio, const std::string &_msg)
{
    if (_prio < m_log_prio)
    {
        boost::mutex::scoped_lock lck(m_condition_mutex);
        m_queue.push(_msg);
        m_condition.notify_one();
    }
}

void logger::msg(int _prio, const char *_msg)
{
    msg(_prio, std::string(_msg));
}

void logger::run()
{
    std::string buffer;
    for (;;)
    {
        boost::mutex::scoped_lock lck(m_condition_mutex);
        while (m_queue.empty() && !m_exit)
            m_condition.wait(lck);

        if (!m_queue.empty())
        {
            m_queue.front().swap(buffer);
            m_queue.pop();

            lck.unlock();
            syslog(LOG_INFO, "%s", buffer.c_str());

        }
        else if (m_exit)
            break;
   }
}

void logger::stop()
{
    m_exit = true;
    m_condition.notify_one();
}

