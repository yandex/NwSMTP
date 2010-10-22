#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/compare.hpp>
#include <iostream>
#include <boost/format.hpp>

#include "server.h"
#include "log.h"

server::server(const server_parameters::remote_point &_listen_point, std::size_t _io_service_pool_size,  uid_t _user, gid_t _group)
        : m_acceptor(m_io_service),
          ssl_context_(m_io_service, boost::asio::ssl::context::sslv23),
          m_new_connection(new smtp_connection(m_io_service, m_connection_manager, ssl_context_)),
          m_io_service_pool_size(_io_service_pool_size)
{

    boost::asio::ip::tcp::resolver resolver(m_acceptor.io_service());
    boost::asio::ip::tcp::resolver::query query(_listen_point.m_host_name, boost::lexical_cast<std::string>(_listen_point.m_port));
    boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
  
    if (g_config.m_use_tls)
    {
        try
        {
            //  ssl_context_.set_options(boost::asio::ssl::context::default_workarounds);
            ssl_context_.set_verify_mode (boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_client_once);
        
            if (!g_config.m_tls_key_file.empty())
            {
                ssl_context_.use_private_key_file(g_config.m_tls_key_file, boost::asio::ssl::context::pem);
            }

            if (!g_config.m_tls_cert_file.empty())
            {
                ssl_context_.use_certificate_file(g_config.m_tls_cert_file, boost::asio::ssl::context::pem);
            }

            /*          if (!g_config.m_tls_ca_file.empty())
                        {
                        ssl_context_.use_certificate_chain_file(g_config.m_tls_ca_file);
                        }*/
        }
        catch (std::exception const& e)
        {       
            g_log.msg(MSG_CRITICAL, str(boost::format("Can't load TLS certificate file: file='%1%', error='%2%'") % g_config.m_tls_key_file % e.what()));
            throw;
        }
    }
  
    m_new_connection.reset(new smtp_connection(m_io_service, m_connection_manager, ssl_context_));
  
    m_acceptor.open(endpoint.protocol());
    m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    m_acceptor.bind(endpoint);
    m_acceptor.listen();

    if (_group && (setgid(_group) == -1))
    {
        g_log.msg(MSG_CRITICAL, "can not change process group id !");    
        throw std::exception();
    }

    if (_user && (setuid(_user) == -1))
    {
        g_log.msg(MSG_CRITICAL, "can not change process user id !");    
        throw std::exception();
    }
  
    m_acceptor.async_accept(
        m_new_connection->socket(), 
        boost::bind(&server::handle_accept, this, boost::asio::placeholders::error)
        );
}

void server::run()
{
    for (std::size_t i = 0; i < m_io_service_pool_size; ++i)
        m_threads_pool.create_thread(boost::bind(&boost::asio::io_service::run, &m_io_service));
}

void server::stop()
{
    boost::mutex::scoped_lock lock(m_mutex);

    m_new_connection.reset();
    m_acceptor.close();

    lock.unlock();

    m_threads_pool.join_all();
}

void server::handle_accept(const boost::system::error_code& e)
{
    boost::mutex::scoped_lock lock(m_mutex);

    bool stopping = m_new_connection.get() == 0;
    if (e == boost::asio::error::operation_aborted || stopping)
        return;  
    
    if (!e)
    {  
        try 
        {
            assert(m_new_connection.get());
            m_new_connection->start();
            m_new_connection.reset(
                new smtp_connection(m_io_service, m_connection_manager, ssl_context_)
                );

        }       
        catch(boost::system::system_error &e)
        {
            if (e.code() != boost::asio::error::not_connected)
            {
                g_log.msg(MSG_NORMAL, str(boost::format("Accept exception: %1%") % e.what()));
            }
        
            m_new_connection.reset(new smtp_connection(m_io_service, m_connection_manager, ssl_context_));
        }
    }
    else
    {
        if (e != boost::asio::error::not_connected)
            g_log.msg(MSG_NORMAL, str(boost::format("Accept error: %1%") % e.message()));       
    }
  
    m_acceptor.async_accept(m_new_connection->socket(),
            boost::bind(&server::handle_accept, this, boost::asio::placeholders::error)
                            );  
}
