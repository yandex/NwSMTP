#if !defined(_SWITCHCFG_H_)
#define _SWITCHCFG_H_

#include <string>
#include <time.h>
#include <boost/thread.hpp>

#include "options.h"

class switchcfg
{
  public:
    
    switchcfg();
        
    void initialize(time_t _fallback_time, time_t _return_time, const server_parameters::remote_point &_primary, const server_parameters::remote_point &_secondary);
        
    server_parameters::remote_point get_primary();
        
    server_parameters::remote_point get_secondary();
        
    void fault();
        
  protected:
        
    time_t m_fallback_time;
    time_t m_return_time;
        
    server_parameters::remote_point m_primary;
    server_parameters::remote_point m_secondary;
        
    bool m_active_secondary;
        
    time_t m_switch_time;                               
        
    boost::mutex m_config_mutex;
};

extern switchcfg g_bb_switch;
extern switchcfg g_so_switch;
extern switchcfg g_av_switch;

#endif // _SWITCHCFG_H_

