#ifndef BASIC_RC_CLIENT
#define BASIC_RC_CLIENT

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind.hpp>
#include <boost/system/error_code.hpp>
#include "yield.hpp"
#include "rc.pb.h"

enum basic_rc_errors
{
    bad_response_id = 1,
    bad_response
};

const boost::system::error_category& get_basic_rc_category();

static const boost::system::error_category& basic_rc_category = get_basic_rc_category();

inline boost::system::error_code make_error_code(basic_rc_errors e)
{
    return boost::system::error_code(
        static_cast<int>(e), basic_rc_category);
}

// --
template <class Request>
class basic_rc_client
{
  public:
    explicit basic_rc_client(boost::asio::io_service& ios);

    // Start asynchronous rcsrv request
    void start(boost::shared_ptr<Request> req, boost::posix_time::time_duration timeout);

    // Stop the last request
    void stop();

    boost::asio::io_service& io_service() { return ios_; }

  private:
    class handle_done;
    class handle_timeout;
    class handle_stop;
    class handle_io;

    boost::asio::io_service& ios_;
    boost::weak_ptr<Request> lastreq_;
};

template <class Handler>
class basic_rc_request
{
    bool done_;
    boost::asio::deadline_timer timer_;
    boost::asio::ip::udp::socket socket_;
    boost::asio::io_service::strand strand_;
    boost::array<char, 512> buf_;
    boost::asio::ip::udp::endpoint host_;
    Handler handler_; // void (const boost::system::error_code&, boost::shared_ptr<Request> req)
    reply_pb a_pb_;

    template <typename Request>
    friend class basic_rc_client;

  public:
    request_pb q_pb;

    basic_rc_request(boost::asio::io_service& ios,
            boost::asio::ip::udp::endpoint endpoint,
            Handler h)
            : done_(false),
              timer_(ios),
              socket_(ios, boost::asio::ip::udp::socket::endpoint_type(
                  boost::asio::ip::udp::v4(), 0)),
              strand_(ios),
              buf_(),
              host_(endpoint),
              handler_(h),
              a_pb_(),
              q_pb()

    {
    }

    boost::asio::ip::udp::endpoint host() const { return host_; }

    const reply_pb& reply() const { return a_pb_; }
};

template <class Request>
class basic_rc_client<Request>::handle_stop
{
    boost::shared_ptr<Request> req_;

  public:
    explicit handle_stop(boost::shared_ptr<Request> req)
            : req_(req)
    {
    }

    void operator()() const
    {
        if (req_->done_)
            return;

        req_->done_ = true;
        try
        {
            req_->timer_.cancel();
            req_->socket_.close();
        }
        catch (...) {}
    }
};

template <class Request>
class basic_rc_client<Request>::handle_done
{
    boost::shared_ptr<Request> req_;

  public:
    explicit handle_done(boost::shared_ptr<Request> req)
            : req_(req)
    {
    }

    void operator()(const boost::system::error_code& ec) const
    {
        if (req_->done_)
            return;

        handle_stop stop(req_);
        stop();
        req_->handler_(ec, req_);
    }
};

template <class Request>
class basic_rc_client<Request>::handle_timeout
{
    boost::shared_ptr<Request> req_;

  public:
    explicit handle_timeout(boost::shared_ptr<Request> req)
            : req_(req)
    {
    }

    void operator()(const boost::system::error_code& ec) const
    {
        if (req_->done_)
            return;

        handle_stop stop(req_);
        stop();
        req_->handler_( make_error_code(boost::system::errc::timed_out), req_ );
    }
};

template <class Request>
class basic_rc_client<Request>::handle_io : private coroutine
{
    boost::shared_ptr<Request> req_;

  public:
    explicit handle_io(boost::shared_ptr<Request> req)
            : req_(req)
    {
    }

    void operator()(const boost::system::error_code& ec = boost::system::error_code(),
            std::size_t size = 0)
    {
        if (req_->done_)
            return;

        handle_done h(req_);

        if (ec)
            return h(ec);

        request_pb& q = req_->q_pb;
        reply_pb& a = req_->a_pb_;

        reenter(*this)
        for(;;)
        {
            // Encode request_pb
            q.SerializeToArray(req_->buf_.data(), req_->buf_.size());

            yield req_->socket_.async_send_to(
                boost::asio::buffer(req_->buf_.data(), q.ByteSize()),
                req_->host_, req_->strand_.wrap(*this));

            yield req_->socket_.async_receive(
                boost::asio::buffer(req_->buf_), req_->strand_.wrap(*this));

            // Decode reply_pb
            if (a.ParseFromArray(req_->buf_.data(),  size))
            {
                if (q.id() != a.id())
                    return h( make_error_code(bad_response_id) );
                return h(boost::system::error_code());
            }
            else
                return h( make_error_code(bad_response) );
        }
    }
};


template <class Request>
basic_rc_client<Request>::basic_rc_client(boost::asio::io_service& ios)
  : ios_(ios),
    lastreq_()
{
}

// Start asynchronous rcsrv request
template <class Request>
void basic_rc_client<Request>::start(boost::shared_ptr<Request> req,
        boost::posix_time::time_duration timeout)
{
    handle_done h(req);
    handle_timeout ht(req);

    // Start asynchronous greylisting query
    handle_io io(req);
    io();

    // Start timer
    req->timer_.expires_from_now(timeout);
    req->timer_.async_wait(req->strand_.wrap(ht));

    // Remeber the request.
    lastreq_ = req;
}

template <class Request>
void basic_rc_client<Request>::stop()
{
    if (boost::shared_ptr<Request> req = lastreq_.lock())
    {
        handle_stop h(req);
        ios_.post(req->strand_.wrap(h));
    }
}

#undef yield

#endif // BASIC_RC_CLIENT
