#include "switchcfg.h"

switchcfg g_bb_switch;

switchcfg g_so_switch;

switchcfg g_av_switch;

switchcfg::switchcfg()
{
}


void switchcfg::initialize( const server_parameters::remote_point &_primary, const server_parameters::remote_point &_secondary)
{
    boost::mutex::scoped_lock lck(m_config_mutex);

    m_primary = _primary;
    m_secondary = _secondary;
}

server_parameters::remote_point switchcfg::get_primary()
{
    boost::mutex::scoped_lock lck(m_config_mutex);
    
    return m_primary;
}

server_parameters::remote_point switchcfg::get_secondary()
{
    boost::mutex::scoped_lock lck(m_config_mutex);

    return m_secondary;
}

