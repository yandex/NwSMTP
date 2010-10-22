#ifndef ATORMOZ_H
#define ATORMOZ_H

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/range.hpp>
#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/bind.hpp>
#include <boost/optional.hpp>

struct rc_result
{
    int ok;
    int sum1;
    int sum2;
    int sum3;
    int sum4;
}; 

struct rc_parameters
{
    std::string ukey;
    std::string login;
    std::string domain;
    std::string size;
};

template<class Handle, class Socket>
void async_rc_put(Socket& s, const typename Socket::endpoint_type& endpoint, const rc_parameters& p, Handle handle);

template<class Handle, class Socket>
void async_rc_get(Socket& s, const typename Socket::endpoint_type& endpoint, const rc_parameters& p, Handle handle);

// --------------------------------------------------------------------------
// impl:

boost::optional<rc_result> parse_rc_response(const boost::asio::streambuf& buf);

template<class Handle>
class handle_rc_read
{
    boost::asio::io_service& ios_;
    boost::shared_ptr<boost::asio::streambuf> buf_;
    Handle handle_;

  public:
    handle_rc_read(boost::asio::io_service& ios, boost::shared_ptr<boost::asio::streambuf> buf, Handle handle)
            : ios_(ios),
              buf_(buf),
              handle_(handle)
    {}

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            if (ec != boost::asio::error::operation_aborted)
            {       
                ios_.post(boost::asio::detail::bind_handler(handle_, ec, boost::optional<rc_result>()));
            }
            return;
        }
        
        boost::optional<rc_result> rc(parse_rc_response(*buf_));
        //      if (rc)
        //          ycout << "### " << boost::make_iterator_range(boost::asio::buffers_begin(buf_->data()), boost::asio::buffers_begin(buf_->data())+sz) << "=> [" 
        //                << rc->ok << "," << rc->sum1 << "," << rc->sum2 << "," << rc->sum3 << "," << rc->sum4 << "]"; // ###
        //      else
        //          ycout << "### " << boost::make_iterator_range(boost::asio::buffers_begin(buf_->data()), boost::asio::buffers_begin(buf_->data())+sz) << "=> [error]";
        ios_.post(boost::asio::detail::bind_handler(handle_, ec, rc));          
    }
};

template<class Handle, class Socket>
class handle_rc_write
{
    Socket& s_;
    boost::shared_ptr<std::string> buf_;
    Handle handle_;

  public:
    handle_rc_write(Socket& s, boost::shared_ptr<std::string>& buf, Handle handle)
            : s_(s),
              buf_(buf),
              handle_(handle)
    {}

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec) 
        {
            if (ec != boost::asio::error::operation_aborted)
            {
                s_.get_io_service().post(boost::asio::detail::bind_handler(handle_, ec, boost::optional<rc_result>()));
            }
            return;
        }
    
        boost::shared_ptr<boost::asio::streambuf> buf(new boost::asio::streambuf);
        boost::asio::async_read_until(s_, *buf, std::string("\r\n0\r\n"),
                handle_rc_read<Handle>(s_.get_io_service(), buf, handle_));
    }
};

template<class Handle, class Socket>
class handle_rc_connect
{
    Socket& s_;
    boost::shared_ptr<std::string> req_;
    Handle handle_;

  public:
    handle_rc_connect(Socket& s, boost::shared_ptr<std::string>& req, Handle handle)
            : s_(s),
              req_(req),
              handle_(handle)
    {}

    void operator()(const boost::system::error_code& ec)
    {
        if (ec)
        {
            if (ec != boost::asio::error::operation_aborted)
            {
                s_.get_io_service().post(boost::asio::detail::bind_handler(handle_, ec, boost::optional<rc_result>()));
            }           
                
            return;
        }
        
        s_.async_write_some(boost::asio::buffer(*req_), 
                handle_rc_write<Handle, Socket>(s_, req_, handle_));
    }
};


template<class Handle, class Socket>
void async_rc_get(Socket& s, const typename Socket::endpoint_type& endpoint, const rc_parameters& p, Handle handle)
{
    boost::shared_ptr<std::string> req(new std::string("GET /rc/get/"));
    req->append(p.ukey).append("/").append(p.login).append("/").
            append(p.domain).append(" HTTP/1.1\r\n\r\n");
    
    s.async_connect(endpoint, handle_rc_connect<Handle, Socket>(s, req, handle));
}

template<class Handle, class Socket>
void async_rc_put(Socket& s, const typename Socket::endpoint_type& endpoint, const rc_parameters& p, Handle handle)
{
    boost::shared_ptr<std::string> req(new std::string("GET /rc/put/"));       
    req->append(p.ukey).append("/").append(p.login).append("/").
            append(p.domain).append("/").append(p.size).append(" HTTP/1.1\r\n\r\n");
    
    s.async_connect(endpoint, handle_rc_connect<Handle, Socket>(s, req, handle));
}

#endif // ATORMOZ_H
