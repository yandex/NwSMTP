#include <stdio.h>
#include <time.h>
#include "timer.h"

using namespace std;

timer::timer()
{
    time(&m_time);
}


void timer::start()
{
    time(&m_time);
}

time_t timer::restart(bool _diff)
{
    time_t ret = mark(_diff);

    time(&m_time);

    return ret;
}

time_t timer::mark(bool _diff)
{
    if (m_time == 0)
        return 0;

    time_t mark;

    time(&mark);

    return _diff ? mark - m_time : mark ;
}

string timer::format_time(time_t _time)
{
    int accu = _time;

    int hours = _time / (60*60);

    accu -= hours * (60*60);

    int min = accu / 60;
    int sec = accu % 60;

    char buffer[200];

    snprintf(buffer, 199, "%02d:%02d:%02d", hours, min, sec);

    return buffer;
}

