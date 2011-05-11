#if !defined(_SWITCHCFG_H_)
#define _SWITCHCFG_H_

#include <string>
#include <time.h>

#include "options.h"

class switchcfg
{
  public:

    switchcfg();

    void initialize(const server_parameters::remote_point &_primary, const server_parameters::remote_point &_secondary);

    server_parameters::remote_point get_primary();

    server_parameters::remote_point get_secondary();

  protected:

    server_parameters::remote_point m_primary;
    server_parameters::remote_point m_secondary;

    boost::mutex m_config_mutex;
};

extern switchcfg g_bb_switch;
extern switchcfg g_so_switch;
extern switchcfg g_av_switch;

#endif // _SWITCHCFG_H_

