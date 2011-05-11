#if !defined(_HTTP_CLIENT_H_)
#define _HTTP_CLIENT_H_

#include <boost/function.hpp>
#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <net/dns_resolver.hpp>


class http_client
        : public boost::enable_shared_from_this<http_client>,
          private boost::noncopyable
{
  public:

    typedef enum { http_method_get, http_method_put } http_method_t;

    http_client(boost::asio::io_service& io_service);

    typedef boost::function< void (const std::string _content) > report_cb;

    // body mast be url encoded
    void start(http_method_t _method, const std::string &_host, unsigned int _service, const std::string &_url, const std::string &_body, unsigned int _timeout);

    void set_callbacks(boost::function< void (const boost::system::error_code& ec, const std::string &_err) > _error,
            boost::function< void (const std::string &_headers) > _headers_read,
            boost::function< void (const std::string &_data, bool _eof) > _response_read);
    void stop();

    boost::asio::ip::tcp::socket& socket();

  protected:
    void do_stop();
    void handle_connect(const boost::system::error_code& ec, y::net::dns::resolver::iterator, int port);
    void handle_resolve(const boost::system::error_code& ec, y::net::dns::resolver::iterator, int port);
    void handle_write_request(const boost::system::error_code &_err);
    void handle_read_status_line(const boost::system::error_code &_err);
    void handle_read_headers(const boost::system::error_code &_err);
    void handle_read_content(const boost::system::error_code &_err);
    void error(const boost::system::error_code& ec, const std::string &_what);

    y::net::dns::resolver m_resolver;
    boost::asio::ip::tcp::socket m_socket;

    boost::asio::streambuf m_request;
    boost::asio::streambuf m_response;

    boost::function< void (const boost::system::error_code& ec, const std::string &_logerrmessage) > on_error;                          // call if error occured
    boost::function< void (const std::string &_headers) > on_headers_read;                      // call if all headers read
    boost::function< void (const std::string &_data, bool _eof) > on_response_read;                     // call if response block read

    boost::asio::deadline_timer m_timer;
    boost::asio::io_service::strand strand_;

    unsigned int m_timer_value;

    void handle_timer( const boost::system::error_code &_error);
    void restart_timeout();
};

typedef boost::shared_ptr<http_client> http_client_ptr;

#endif // _HTTP_CLIENT_H_
