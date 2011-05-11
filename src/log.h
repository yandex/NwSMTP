#if !defined(_LOG_H_)
#define _LOG_H_

#include <syslog.h>
#include <string>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>
#include <queue>

const int MSG_NORMAL    =       20;
const int MSG_CRITICAL  =       10;
const int MSG_VERY_CRITICAL     =       10;

class logger
{
  public:
    logger();

    void initlog(const std::string &_info, int _log_prio);

    void msg(int _prio, const std::string &_msg);

    void msg(int _prio, const char *_msg);

    void run();

    void stop();

  protected:

    std::queue<std::string> m_queue;

    boost::mutex m_condition_mutex;
    boost::condition m_condition;

    bool m_exit;
    int m_log_prio;

};

extern logger g_log;

#endif // _LOG_H_

