#ifndef RC_CHECK_H
#define RC_CHECK_H

#include <boost/asio/handler_invoke_hook.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>
#include <boost/lexical_cast.hpp>
#include <string>
#include "socket_pool_service.h"
#include "atormoz.h"
#include "uti.h"

class rc_check
        : public boost::enable_shared_from_this<rc_check>
{
  public:
    typedef std::vector< std::pair<std::string,
                                   boost::asio::ip::tcp::endpoint> > rclist;

  private:
    boost::asio::io_service& ios_;
    std::string email_;
    rc_parameters p_;
    rclist l_;
    rclist::iterator lit_;
    unsigned long ukeyh_;
    int timeout_;
    typedef boost::asio::ip::tcp::socket socket_type;
    struct request;
    boost::weak_ptr<request> lastreq_;

    enum rc_op { GET, PUT};

    static unsigned long get_uid_hash(const std::string& uid)
    {
	union
	{
	    unsigned char bytes[sizeof (long long int)];
	    long long int lli;
	} uuid;
	uuid.lli = atoll(uid.c_str());
	return djb2_hash(uuid.bytes, sizeof(uuid.bytes));
    };

    struct request
    {
        typedef boost::asio::ip::tcp::socket socket_type;
        typedef boost::function<void (const boost::system::error_code&,
                               boost::optional<rc_result>)> Handler;
        Handler handler;
        rc_op op;
        bool done;
        socket_type socket;
        boost::asio::deadline_timer t;
        boost::asio::io_service::strand strand;
        boost::weak_ptr<rc_check> q;
        request(boost::asio::io_service& ios, Handler h, rc_op o, boost::weak_ptr<rc_check> d)
                : handler(h),
                  op(o),
                  done(false),
                  socket(ios),
                  t(ios),
                  strand(ios),
                  q(d)
        {
        }
    };

    class handle_done
    {
        int attempt_;
        boost::shared_ptr<request> req_;

      public:
        handle_done(int attempt, boost::shared_ptr<request> req)
                : attempt_(attempt), req_(req)
        {
        }

        void operator()(const boost::system::error_code& ec,
                        boost::optional<rc_result> rc = boost::optional<rc_result>())
        {
            if (req_->done)
                return;

            if (!ec) // timeout or success, depending on rc
            {
                boost::shared_ptr<rc_check> q = req_->q.lock();
                if (!q)
                    return;

                if (rc)
                {
                    handle_stop h(req_);
                    h();
                    return q->ios_.post(boost::bind(req_->handler, ec, rc));
                }
            }
            else if (ec == boost::asio::error::operation_aborted)
                return;

            boost::shared_ptr<rc_check> q = req_->q.lock();
            if (!q)
                return;

            handle_stop h(req_);
            h();

            // the last request failed
            if  ((attempt_ == 0)         // already a second attempt => fail
                 && (q->l_.size() > 1))      // no more rc hosts => fail
            {
                // try with another host
                rclist::iterator newlit = q->lit_;
                if (++newlit == q->l_.end())
                    newlit = q->l_.begin();
                q->lit_ = newlit;
                boost::shared_ptr<request> newreq(new request(q->ios_, req_->handler, req_->op, q));
                return newreq->op == GET
                        ? q->get_helper(newreq, ++attempt_)
                        : q->put_helper(newreq, ++attempt_);
            }
            q->ios_.post(boost::bind(req_->handler, ec, rc));
        }
    };

    void get_helper(boost::shared_ptr<request> req, int attempt)
    {
        handle_done h(attempt, req);
        lastreq_ = req;
        async_rc_get(req->socket, lit_->second, p_, req->strand.wrap(h));
        req->t.expires_from_now(boost::posix_time::seconds(timeout_));
        req->t.async_wait(req->strand.wrap(h));
    }

    void put_helper(boost::shared_ptr<request> req, int attempt)
    {
        handle_done h(attempt, req);
        lastreq_ = req;
        async_rc_put(req->socket, lit_->second, p_, req->strand.wrap(h));
        req->t.expires_from_now(boost::posix_time::seconds(timeout_));
        req->t.async_wait(req->strand.wrap(h));
    }

    friend class handle_get;
    friend class handle_put;
    friend class handle_timeout;

    class handle_stop
    {
      public:
        boost::shared_ptr<request> req;

        explicit handle_stop(boost::shared_ptr<request> r)
                : req(r)
        {
        }

        void operator()() const
        {
            if (req->done)
                return;

            req->done = true;
            try
            {
                req->t.cancel();
                req->done = true;
                req->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
                req->socket.close();
            }
            catch (...) {}
        }
    };

  public:
    rc_check(boost::asio::io_service& ios, const std::string& email,
            const std::string& uid, const rclist& list, int timeout)
            : ios_(ios),
              email_(email),
              l_(list),
              timeout_(timeout)
    {
        // get rc host endpoint for this recipient
        ukeyh_ = get_uid_hash(uid);
        int idx = (ukeyh_ % l_.size());
        lit_ = l_.begin() + idx;
        p_.ukey = uid;
        parse_email(email, p_.login, p_.domain);
    }

    void stop()
    {
        if (boost::shared_ptr<request> req = lastreq_.lock())
        {
            handle_stop h(req);
            ios_.post(req->strand.wrap(h));
        }
    }

    inline const rc_parameters& get_parameters() const
    {   return p_;   }

    inline const std::string& get_hostname() const
    {   return lit_->first;   }

    const std::string& get_email() const
    {   return email_;  }

    template <class Handler>
    void get(Handler handler)
    {
        int idx = (ukeyh_ % l_.size());
        lit_ = l_.begin() + idx;

        boost::shared_ptr<request> req(
            new request(ios_, handler, GET, shared_from_this()));
        ios_.post(req->strand.wrap(
            boost::bind(&rc_check::get_helper, shared_from_this(), req, 0)));
    }

    template <class Handler>
    void put(Handler handler, int size)
    {
        int idx = (ukeyh_ % l_.size());
        lit_ = l_.begin() + idx;

        p_.size = boost::lexical_cast<std::string>(size);
        boost::shared_ptr<request> req(
            new request(ios_, handler, PUT, shared_from_this()));
        ios_.post(req->strand.wrap(
            boost::bind(&rc_check::put_helper, shared_from_this(), req, 0)));
    }
};

#endif //RC_CHECK_H
