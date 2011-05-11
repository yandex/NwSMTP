#include <iostream>
#include <istream>
#include <ostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>

#include "http_client.h"


using boost::asio::ip::tcp;
using namespace y::net;

http_client::http_client(boost::asio::io_service& io_service)
        : m_resolver(io_service),
          m_socket(io_service),
          m_timer(io_service),
          strand_(io_service)
{
}

void http_client::start(http_method_t _method, const std::string &_host, unsigned int _service, const std::string &_url, const std::string &_body, unsigned int _timeout)
{
    m_timer_value = _timeout;

    std::ostream request_stream(&m_request);

    if (_method == http_method_get)
    {
        request_stream << "GET " << _url << " HTTP/1.0\r\n";
        request_stream << "Host: " << _host << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";
    }
    else
    {
        request_stream << "POST " << _url << " HTTP/1.0\r\n";
        request_stream << "Host: " << _host << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n";
        request_stream << "Content-Length: " << _body.length() << "\r\n";
        request_stream << "Content-Type: application/x-www-form-urlencoded" << "\r\n\r\n";
        request_stream << _body;
    }

    m_resolver.async_resolve(
        _host,
        dns::type_a,
        boost::bind(&http_client::handle_resolve,
                shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::iterator,
                _service)
        );
}

void http_client::handle_resolve(const boost::system::error_code& ec, dns::resolver::iterator it, int port)
{
    if (!ec)
    {
        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), port);
        try
        {
            m_socket.async_connect(point,
                    strand_.wrap(
                        boost::bind(&http_client::handle_connect,
                                shared_from_this(),
                                boost::asio::placeholders::error,
                                ++it,
                                port))
                                   );
        }
        catch(boost::system::system_error &e)
        {
            error(ec, e.what());
        }
    }
    else
    {
        error(ec, ec.message());
    }
}

void http_client::handle_connect(const boost::system::error_code& ec, dns::resolver::iterator it, int port)
{
    if (!ec)
    {
        restart_timeout();

        boost::asio::async_write(m_socket, m_request,
                strand_.wrap(boost::bind(&http_client::handle_write_request,
                                shared_from_this(), boost::asio::placeholders::error)) );
    }
    else if (it != dns::resolver::iterator())
    {
        boost::asio::ip::tcp::endpoint point(boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), port);
        m_socket.async_connect(point,
                strand_.wrap(
                    boost::bind(&http_client::handle_connect,
                            shared_from_this(),
                            boost::asio::placeholders::error,
                            ++it,
                            port))
                               );
    }
    else
    {
        error(ec, ec.message());
    }
}

void http_client::handle_write_request(const boost::system::error_code& _err)
{
    if (!_err)
    {
        boost::asio::async_read_until(m_socket, m_response, "\r\n",
                strand_.wrap(boost::bind(&http_client::handle_read_status_line,
                                shared_from_this(), boost::asio::placeholders::error)));
    }
    else
    {
        error(_err, _err.message());
    }
}

void http_client::handle_read_status_line(const boost::system::error_code& _err)
{
    if (!_err)
    {
        std::istream response_stream(&m_response);

        std::string http_version;
        response_stream >> http_version;

        unsigned int status_code;
        response_stream >> status_code;

        std::string status_message;
        std::getline(response_stream, status_message);

        if (!response_stream || http_version.substr(0, 5) != "HTTP/")
        {
            error(_err, "Invalid response from HTTP server");
            return;
        }
        if (status_code != 200)
        {
            char buffer[200];
            snprintf(buffer, sizeof(buffer)-1, "Invalid response from HTTP server, code=%d", status_code);
            error(_err, buffer);
            return;
        }

        // Read the response headers, which are terminated by a blank line.
        boost::asio::async_read_until(m_socket, m_response, "\r\n\r\n",
                strand_.wrap(boost::bind(&http_client::handle_read_headers, shared_from_this(),
                                boost::asio::placeholders::error)));
    }
    else
    {
        error(_err, _err.message());
    }
}

void http_client::handle_read_headers(const boost::system::error_code& _err)
{
    if (!_err)
    {
        // Process the response headers.
        std::istream response_stream(&m_response);
        std::string header;

        std::string collect_header;

        while (std::getline(response_stream, header) && header != "\r")
        {
            collect_header.append(header + "\n");
        }

        if (!collect_header.empty())
        {

            if (on_headers_read)
                on_headers_read(collect_header);                        // callback
            on_headers_read.clear();
        }

        // process content read

        if (m_response.size() > 0)
        {
            std::stringstream ss;
            ss << response_stream.rdbuf();                                      // glue all read buffers

            if (on_response_read)
                on_response_read(ss.str(), false);                      // callback
        }

        // Start reading remaining data until EOF.
        boost::asio::async_read(m_socket, m_response,
                boost::asio::transfer_at_least(1),
                strand_.wrap(boost::bind(
                    &http_client::handle_read_content, shared_from_this(),
                    boost::asio::placeholders::error))
                                );
    }
    else
    {
        error(_err, _err.message());
    }
}

void http_client::handle_read_content(const boost::system::error_code& _err)
{
    if (_err && (_err != boost::asio::error::eof))                   // error
    {
        error(_err, _err.message());
    }
    else
    {
    
	if ((m_response.size() == 0) || (_err == boost::asio::error::eof))
	{
    	    if (on_response_read)
        	on_response_read("", true);
            
    	    on_error.clear();
    	    on_headers_read.clear();
    	    on_response_read.clear();
	}
	else
        {
            std::istream response_stream(&m_response);
            std::stringstream ss;
            ss << response_stream.rdbuf();
            

            if (on_response_read)
                on_response_read(ss.str(), false);                      // callback

    	    // Continue reading remaining data until EOF.

        	boost::asio::async_read(m_socket,
            	    m_response,
            	    boost::asio::transfer_at_least(1),
            	    strand_.wrap(boost::bind(&http_client::handle_read_content,
                                shared_from_this(), boost::asio::placeholders::error)));
	}
    }	
}

boost::asio::ip::tcp::socket& http_client::socket()
{
    return m_socket;
}

void http_client::error(const boost::system::error_code& ec, const std::string &_what)
{
    stop();
    if (on_error)
        on_error(ec, _what);
    on_error.clear();
    on_headers_read.clear();
    on_response_read.clear();
}

void http_client::set_callbacks(boost::function< void (const boost::system::error_code& ec, const std::string &_err) > _error,
        boost::function< void (const std::string &_headers) > _headers_read,
        boost::function< void (const std::string &_data, bool _eof) > _response_read)
{
    on_error = _error;
    on_headers_read = _headers_read;
    on_response_read = _response_read;
}

void http_client::do_stop()
{
    try
    {
        m_resolver.cancel();
        m_timer.cancel();
        m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        m_socket.close();
    }
    catch(...)
    {
    }
}

void http_client::stop()
{
    m_socket.get_io_service().post(strand_.wrap(boost::bind(&http_client::do_stop, shared_from_this())));
}

void http_client::handle_timer(const boost::system::error_code& _e)
{
    if (!_e)
    {
        error(_e, "Server connection timeout");
    }
}

void http_client::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(
        strand_.wrap(
            boost::bind(&http_client::handle_timer,
                    shared_from_this(), boost::asio::placeholders::error))
        );
}
