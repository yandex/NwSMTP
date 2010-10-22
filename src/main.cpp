#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <pthread.h>
#include <signal.h>
#include <boost/format.hpp>

#include "server.h"
#include "options.h"
#include "log.h"
#include "aliases.h"
#include "pidfile.h"
#include "ip_options.h"

int main(int argc, char* argv[])
{
    
    if (!g_config.parse_config(argc, argv, std::cout))
    {
        return 200;
    }
    
    if (!g_config.m_foreground)
    {
        if (daemon(0, 0) < 0)
        {
            perror("Can't demonize !");
            exit(3);
        }
    }

    g_log.initlog("nwsmtp", 9999);
    boost::thread log(boost::bind(&logger::run, &g_log));
    
    if (g_config.m_so_check && !g_config.m_so_file_path.empty())
    {
        g_log.msg(MSG_NORMAL,str(boost::format("Primary SO host: host='%1%:%2%'") % g_config.m_so_primary_host.m_host_name % g_config.m_so_primary_host.m_port));
    }   

    if (g_config.m_bb_check && !g_config.m_bb_file_path.empty())
    {
        g_log.msg(MSG_NORMAL,str(boost::format("Primary black_box host: host='%1%:%2%%3%'") % g_config.m_bb_primary_host.m_host_name % g_config.m_bb_primary_host.m_port % g_config.m_bb_primary_host.m_url));
    }   
    
    try
    {
        g_bb_switch.initialize( g_config.m_bb_fallback_time, g_config.m_bb_return_time, g_config.m_bb_primary_host, g_config.m_bb_secondary_host);
        g_so_switch.initialize( g_config.m_so_fallback_time, g_config.m_so_return_time, g_config.m_so_primary_host, g_config.m_so_secondary_host);
        g_av_switch.initialize( g_config.m_av_fallback_time, g_config.m_av_return_time, g_config.m_av_primary_host, g_config.m_av_secondary_host);
        
        if (g_aliases.load(g_config.m_aliases_file))
        {
            g_log.msg(MSG_NORMAL,str(boost::format("Load aliases file: name='%1%'") % g_config.m_aliases_file));
        }
        else
        {
            g_log.msg(MSG_VERY_CRITICAL,str(boost::format("Can't load aliases file: name='%1%'") % g_config.m_aliases_file));
            throw std::exception();
        }
        
        if (!g_config.m_ip_config_file.empty())
        {
            if (g_ip_config.load(g_config.m_ip_config_file))
            {
                g_log.msg(MSG_NORMAL,str(boost::format("Load IP restriction file: name='%1%'") % g_config.m_ip_config_file));
            }
            else
            {
                g_log.msg(MSG_NORMAL,str(boost::format("Can't load IP restriction file: name='%1%'") % g_config.m_ip_config_file));
            }
        }    
        
        g_log.msg(MSG_NORMAL, "Start process...");
    
        sigset_t new_mask;
        sigfillset(&new_mask);
        sigset_t old_mask;
        pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);
    
        server s(g_config.m_listen_point, g_config.m_worker_count, g_config.m_uid, g_config.m_gid );
        s.run();
        
        if (!g_pid_file.create(g_config.m_pid_file))
        {
            g_log.msg(MSG_NORMAL,str(boost::format("Can't write PID file: name='%1%', error='%2%'") % g_config.m_pid_file % strerror(errno)));
        }
        
        while(true)
        {
            pthread_sigmask(SIG_SETMASK, &old_mask, 0);

            sigset_t wait_mask;
            sigemptyset(&wait_mask);
            sigaddset(&wait_mask, SIGINT);
            sigaddset(&wait_mask, SIGQUIT);
            sigaddset(&wait_mask, SIGTERM);
            sigaddset(&wait_mask, SIGHUP);
            pthread_sigmask(SIG_BLOCK, &wait_mask, 0);
            int sig = 0;
            
            sigwait(&wait_mask, &sig);
            
            if (sig == SIGHUP)
            {
                if (g_aliases.load(g_config.m_aliases_file))
                {
                    g_log.msg(MSG_NORMAL,str(boost::format("Reload aliases file: name='%1%'") % g_config.m_aliases_file));
                }
                else
                {
                    g_log.msg(MSG_VERY_CRITICAL,str(boost::format("Can't reload aliases file: name='%1%'") % g_config.m_aliases_file));
                }
                
                continue;
            }
            
            g_log.msg(MSG_NORMAL,str(boost::format("Received signal: %1%, exiting...") % sig));
            
            break;
        }    
        
        s.stop();
        g_log.msg(MSG_NORMAL, "Normal end process...");
        
    }
    catch (std::exception &e)
    {
        g_log.msg(MSG_NORMAL, str(boost::format("Can't start server process: %1%") % e.what()));
    }
    
    g_pid_file.unlink();
    
    g_log.stop();
    log.join();
    
    return 0;
}
