#include "switchcfg.h"

switchcfg g_bb_switch;

switchcfg g_so_switch;

switchcfg g_av_switch;
    
switchcfg::switchcfg()
{
}

        
void switchcfg::initialize(time_t _fallback_time, time_t _return_time, const server_parameters::remote_point &_primary, const server_parameters::remote_point &_secondary)
{
    boost::mutex::scoped_lock lck(m_config_mutex);
    
    m_fallback_time = _fallback_time;
    m_return_time = _return_time;
    
    m_primary = _primary;
    m_secondary = _secondary;
    
    m_switch_time = 0;
    m_active_secondary = false;
}

server_parameters::remote_point switchcfg::get_primary()
{
    boost::mutex::scoped_lock lck(m_config_mutex);
    
    time_t now;
    time(&now);
    
    if (m_active_secondary && (m_switch_time > 0) && (now > m_switch_time))
    {
        m_switch_time = 0;
        m_active_secondary = false;
    }
    else if (!m_active_secondary && (m_switch_time > 0) && (now > m_switch_time))
    {
        m_switch_time = 0;
    }
    
    return m_active_secondary ? m_secondary : m_primary;

}
        
server_parameters::remote_point switchcfg::get_secondary()
{
    boost::mutex::scoped_lock lck(m_config_mutex);
    
    return m_secondary;
}
        
void switchcfg::fault()
{
    boost::mutex::scoped_lock lck(m_config_mutex);
    
    time_t now;
    time(&now);

    if (m_active_secondary)
    {
        return;
    }
    
    if (m_switch_time == 0)
    {
        m_switch_time = now + m_fallback_time;
    }
    else
    {
        m_switch_time = now + m_return_time;
        m_active_secondary = true;
    }
}
