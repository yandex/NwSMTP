#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <pthread.h>
#include <signal.h>
#include <boost/format.hpp>

#if defined(HAVE_PA_ASYNC_H)
#include <pa/async.h>
#endif

#include "server.h"
#include "options.h"
#include "log.h"
#include "aliases.h"
#include "pidfile.h"
#include "ip_options.h"

namespace {
void log_err(int prio, const std::string& what, bool copy_to_stderr)
{
    g_log.msg(prio, what);
    if (copy_to_stderr)
        std::cerr << what << std::endl;
}
}

int main(int argc, char* argv[])
{
    bool daemonized = false;
    if (!g_config.parse_config(argc, argv, std::cout))
    {
        return 200;
    }

    g_log.initlog("nwsmtp", 9999);
    boost::thread log;

#if defined(HAVE_HOSTSEARCH_HOSTSEARCH_H)
    if (g_config.m_so_check && !g_config.m_so_file_path.empty())
    {
        g_log.msg(MSG_NORMAL,str(boost::format("Primary SO host: host='%1%:%2%'") % g_config.m_so_primary_host.m_host_name % g_config.m_so_primary_host.m_port));
    }

    if (g_config.m_bb_check && !g_config.m_bb_file_path.empty())
    {
        g_log.msg(MSG_NORMAL,str(boost::format("Primary black_box host: host='%1%:%2%%3%'") % g_config.m_bb_primary_host.m_host_name % g_config.m_bb_primary_host.m_port % g_config.m_bb_primary_host.m_url));
    }
#endif

    int rval = 0;
    try
    {
        g_bb_switch.initialize( g_config.m_bb_primary_host, g_config.m_bb_secondary_host);
        g_so_switch.initialize( g_config.m_so_primary_host, g_config.m_so_secondary_host);
        g_av_switch.initialize( g_config.m_av_primary_host, g_config.m_av_secondary_host);


        if (!g_config.m_aliases_file.empty())
        {
            if (g_aliases.load(g_config.m_aliases_file))
	    {
    	        g_log.msg(MSG_NORMAL,str(boost::format("Load aliases file: name='%1%'") % g_config.m_aliases_file));
    	    }
    	    else
    	    {
        	throw std::logic_error(str(boost::format("Can't load aliases file: name='%1%'") % g_config.m_aliases_file));
    	    }
        }

        if (!g_config.m_ip_config_file.empty())
        {
            if (g_ip_config.load(g_config.m_ip_config_file))
            {
                g_log.msg(MSG_NORMAL,str(boost::format("Load IP restriction file: name='%1%'") % g_config.m_ip_config_file));
            }
            else
            {
        	throw std::logic_error(str(boost::format("Can't load IP restriction file: name='%1%'") % g_config.m_ip_config_file));
            }
        }

        g_log.msg(MSG_NORMAL, "Start process...");

        sigset_t new_mask;
        sigfillset(&new_mask);
        sigset_t old_mask;
        pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

        server s(g_config.m_worker_count, g_config.m_uid, g_config.m_gid );

        // Daemonize as late as possible, so as to be able to copy fatal error to stderr in case the server can't start
        if (!g_config.m_foreground)
        {
            if (daemon(0, 0) < 0)
                throw std::runtime_error("Failed to daemonize!");
            daemonized = true;
        }

#if defined(HAVE_PA_ASYNC_H)
        pa::async_profiler::init(1000000, 500);
#endif

        // Start logging thread
        boost::thread(boost::bind(&logger::run, &g_log)).swap(log);

        s.run();

        if (!g_pid_file.create(g_config.m_pid_file))
        {
            log_err(MSG_NORMAL, str(boost::format("Can't write PID file: name='%1%', error='%2%'") % g_config.m_pid_file % strerror(errno)),
                    !daemonized);
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
                    log_err(MSG_VERY_CRITICAL,str(boost::format("Can't reload aliases file: name='%1%'") % g_config.m_aliases_file),
                            !daemonized);
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
        log_err(MSG_NORMAL, str(boost::format("Can't start server process: %1%") % e.what()), !daemonized);
        rval = 200;
    }

    g_pid_file.unlink();

    // If an exception occured before the creation of the logging thread we need to create it here to log pending errors
    if (log.get_id() == boost::thread::id())
        boost::thread(boost::bind(&logger::run, &g_log)).swap(log);

    g_log.stop();
    log.join();

    return rval;
}
