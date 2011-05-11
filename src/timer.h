#if !defined(_TIMER_H_)
#define _TIMER_H_

#include <string>

class timer
{
  public:
    timer();

    void start();

    time_t mark(bool _diff=true);
    time_t restart(bool _diff=true);

    static      std::string format_time(time_t _time);

  protected:
    time_t m_time;
};

#endif
