#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/compare.hpp>
#include <iostream>
#include <boost/format.hpp>

#include "server.h"
#include "log.h"

server::server(std::size_t _io_service_pool_size,  uid_t _user, gid_t _group)
        : ssl_context_(m_io_service, boost::asio::ssl::context::sslv23),
          m_io_service_pool_size(_io_service_pool_size)
{

    if (g_config.m_use_tls)
    {
        try
        {
            //            ssl_context_.set_verify_mode (boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_client_once);
            ssl_context_.set_verify_mode (asio::ssl::context::verify_none);

            ssl_context_.set_options (
                asio::ssl::context::default_workarounds
                | asio::ssl::context::no_sslv2 );


            if (!g_config.m_tls_cert_file.empty())
            {
                ssl_context_.use_certificate_chain_file(g_config.m_tls_cert_file);
            }
            if (!g_config.m_tls_key_file.empty())
            {
                ssl_context_.use_private_key_file(g_config.m_tls_key_file, boost::asio::ssl::context::pem);
            }
        }
        catch (std::exception const& e)
        {
            throw std::runtime_error(str(boost::format("Can't load TLS key / certificate file: file='%1%', error='%2%'") % g_config.m_tls_key_file % e.what()));
        }
    }

    std::for_each(g_config.m_listen_points.begin(), g_config.m_listen_points.end(),
            boost::bind(&server::setup_acceptor, this, _1, false)
                  );

    if (g_config.m_use_tls)
        std::for_each(g_config.m_ssl_listen_points.begin(), g_config.m_ssl_listen_points.end(),
                boost::bind(&server::setup_acceptor, this, _1, true)
                      );

    if ( acceptors_.empty() )
    {
        throw std::logic_error("No address to bind to!");
    }

    if (_group && (setgid(_group) == -1))
    {
        g_log.msg(MSG_CRITICAL, "Cannot change process group id !");
        throw std::exception();
    }

    if (_user && (setuid(_user) == -1))
    {
        g_log.msg(MSG_CRITICAL, "Cannot change process user id !");
        throw std::exception();
    }

}

bool server::setup_acceptor(const std::string& address, bool ssl)
{
    std::string::size_type pos = address.find(":");

    if (pos == std::string::npos)
        return false;

    boost::asio::ip::tcp::resolver resolver(m_io_service);
    boost::asio::ip::tcp::resolver::query query(address.substr(0,pos), address.substr(pos+1));
    boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);

    smtp_connection_ptr connection;
    connection.reset(new smtp_connection(m_io_service, m_connection_manager, ssl_context_));

    boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor( new boost::asio::ip::tcp::acceptor(m_io_service) );
    acceptors_.push_front(acceptor);

    acceptor->open(endpoint.protocol());
    acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor->bind(endpoint);
    acceptor->listen();

    acceptor->async_accept(connection->socket(),
            boost::bind(&server::handle_accept, this, acceptors_.begin(), connection, ssl,  boost::asio::placeholders::error)
                           );
    return true;
}


void server::run()
{
    for (std::size_t i = 0; i < m_io_service_pool_size; ++i)
        m_threads_pool.create_thread(boost::bind(&boost::asio::io_service::run, &m_io_service));
}

void server::stop()
{
    boost::mutex::scoped_lock lock(m_mutex);

    std::for_each(acceptors_.begin(), acceptors_.end(), boost::bind(&acceptor_ptr::value_type::close, _1));

    lock.unlock();

    m_threads_pool.join_all();
    acceptors_.clear();
}

void server::handle_accept(acceptor_list::iterator acceptor, smtp_connection_ptr _connection, bool _force_ssl, const boost::system::error_code& e)
{
    boost::mutex::scoped_lock lock(m_mutex);

    if (e == boost::asio::error::operation_aborted)
        return;

    if (!e)
    {
        try
        {
            _connection->start( _force_ssl );

        }
        catch(boost::system::system_error &e)
        {
            if (e.code() != boost::asio::error::not_connected)
            {
                g_log.msg(MSG_NORMAL, str(boost::format("Accept exception: %1%") % e.what()));
            }
        }
        _connection.reset(new smtp_connection(m_io_service, m_connection_manager, ssl_context_));
    }
    else
    {
        if (e != boost::asio::error::not_connected)
            g_log.msg(MSG_NORMAL, str(boost::format("Accept error: %1%") % e.message()));
    }

    (*acceptor)->async_accept(_connection->socket(),
            boost::bind(&server::handle_accept, this, acceptor, _connection, _force_ssl, boost::asio::placeholders::error)
                           );
}
