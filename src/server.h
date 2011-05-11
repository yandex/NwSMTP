#if !defined(_SERVER_H_)
#define _SERVER_H_

#include <boost/asio.hpp>
#include <string>
#include <list>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio/ssl.hpp>

#include "smtp_connection.h"
#include "smtp_connection_manager.h"
#include "options.h"

class server
        : private boost::noncopyable
{
  public:

    explicit server(std::size_t _io_service_pool_size, uid_t _user = 0, gid_t _group = 0);

    void run();

    void stop();

  private:
    typedef boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_ptr;
    typedef std::list<acceptor_ptr> acceptor_list;

    bool setup_acceptor(const std::string& address, bool ssl);
    void handle_accept(acceptor_list::iterator acceptor, smtp_connection_ptr _connection, bool force_ssl, const boost::system::error_code& e);

    boost::asio::io_service m_io_service;

    acceptor_list acceptors_;

    boost::asio::ssl::context ssl_context_;

    smtp_connection_manager m_connection_manager;

    std::size_t m_io_service_pool_size;

    boost::thread_group m_threads_pool;

    boost::mutex m_mutex;
};

#endif // _SERVER_H_
