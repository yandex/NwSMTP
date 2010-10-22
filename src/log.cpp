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
    
    while (!m_exit)
    {

        {
            boost::mutex::scoped_lock lck(m_condition_mutex);

            while (m_queue.size() == 0)
            {
                m_condition.wait(lck);

                if (m_exit && (m_queue.size() == 0))
                {
                    return;
                }
            }

            buffer  = m_queue.front();
            m_queue.pop();
        }
                
        syslog(LOG_INFO, "%s", buffer.c_str());
        //      std::cout<< "Msg:" << buffer << std::endl;
    }   
}
        
void logger::stop()
{
    m_exit = true;
    m_condition.notify_one();
}

