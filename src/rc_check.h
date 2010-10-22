#ifndef RC_CHECK_H
#define RC_CHECK_H

#include <string>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
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
    //    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, 
    //  socket_pool_service<boost::asio::ip::tcp> > socket_type;        
    typedef boost::asio::ip::tcp::socket socket_type;
    boost::asio::io_service& ios_;
    socket_type sock_;
    boost::asio::deadline_timer t_;
    std::string email_;
    std::string host_;
    rc_parameters p_;
    rclist l_;
    rclist::iterator lit_;
    unsigned long ukeyh_;
    boost::asio::io_service::strand strand_;
    int timeout_;
    bool stop_pending_;
  
    enum rc_op { GET, PUT};

    template <class Handler>
    struct request
    {
        Handler handler;
        rc_op op;
        bool done;
        boost::weak_ptr<rc_check> q;    

        request(Handler h, rc_op o, boost::weak_ptr<rc_check> qq)
                : handler(h),
                  op(o),
                  done(false),
                  q(qq)
        {
        }
    };

    template <class Handler>
    class handle_done
    {
        int attempt_;
        boost::shared_ptr<request<Handler> > req_;

      public:
        handle_done(int attempt, boost::shared_ptr<request<Handler> > req)
                : attempt_(attempt), req_(req)
        {
        }

        void operator()(const boost::system::error_code& ec, boost::optional<rc_result> rc)
        {
            if (req_->q.expired() || req_->done)
                return;

            else if (ec == boost::asio::error::operation_aborted)
            {
                boost::shared_ptr<rc_check> q = req_->q.lock();
                if (q->stop_pending_)
                    q->do_stop();
                return;
            }

            boost::shared_ptr<rc_check> q = req_->q.lock();
            q->cancel();

            while (true)
            {
                if (!rc)
                {
                    int hcount = q->l_.size();
                    bool fail = (attempt_ > 0) || // already a second attempt => rc fail
                            (hcount < 2); // no more rc hosts => rc fail
                    if (fail)
                        break;

                    // try with another host
                    //              ycout << q->this_ << "\t:rc::handle_done(): try with another host"; // ###
                    rclist::iterator newlit = q->l_.begin() + q->ukeyh_ % (hcount -1);
                    while (newlit == q->lit_)
                    {
                        if (++newlit == q->l_.end())
                            newlit = q->l_.begin();        
                    }
                    q->lit_ = newlit;
                    q->host_ = q->lit_->first;
                    if (req_->op == GET)
                        return q->get_helper(req_, ++attempt_);
                    else
                        return q->put_helper(req_, ++attempt_);
                }
                break;
            }

            /* ycout << q->this_ << "\t:rc::handle_done(): posting completion handler: email=" << q->email_ << ", ec=" << ec.message();  // ### */
            req_->done = true;      
            q->do_stop();
            q->ios_.post(boost::bind(req_->handler, ec, rc));
        }
    };  

    template <class Handler>
    class handle_timeout
    {
        boost::shared_ptr<request<Handler> > req_;

      public:
        handle_timeout(boost::shared_ptr<request<Handler> > req)
                : req_(req)
        {
        }

        void operator()(const boost::system::error_code& ec)
        {
            if (req_->q.expired() || req_->done) 
                return;

            boost::shared_ptr<rc_check> q = req_->q.lock();

            if (ec != boost::asio::error::operation_aborted)
            {
                req_->done = true;
                q->stop();
                q->ios_.post(boost::bind(req_->handler, boost::asio::error::timed_out, 
                                boost::optional<rc_result>()));
            }       
        }
    };

    template <class Handler>
    void get_helper(boost::shared_ptr<request<Handler> > req, int attempt)
    {    
        //      ycout << this_ << "\t:async_rc_get: email=" << email_ << ", att=" << attempt; // ###    
        async_rc_get(sock_, lit_->second, p_, 
                strand_.wrap(handle_done<Handler>(attempt, req)));
        t_.expires_from_now(boost::posix_time::seconds(timeout_)); 
        t_.async_wait(strand_.wrap(handle_timeout<Handler>(req)));
    }

    template <class Handler>
    void put_helper(boost::shared_ptr<request<Handler> > req, int attempt)
    {   
        /*      ycout << this_ << "\t" << boost::posix_time::microsec_clock::local_time() << "\t:async_rc_put: email=" << email_ << ", att=" << attempt; // ###  */
        async_rc_put(sock_, lit_->second, p_, 
                strand_.wrap(handle_done<Handler>(attempt, req)));
        t_.expires_from_now(boost::posix_time::seconds(timeout_));
        t_.async_wait(strand_.wrap(handle_timeout<Handler>(req)));
    }
    
    template <class Handler> friend class handle_get;
    template <class Handler> friend class handle_put;
    template <class Handler> friend class handle_timeout;

    void cancel()
    {
        //      ycout << this_ << "\t:rc_check::cancel()"; // ###
        t_.cancel();
        try {
            sock_.cancel();         
        } catch (...) {}        
    }

    void do_stop()
    {
        stop_pending_ = false;
        t_.cancel();
        try {
            sock_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            sock_.close();
        } catch (...) {}
    }

  public:
    rc_check(boost::asio::io_service& ios, const std::string& email, const std::string& uid, const rclist& list, int timeout)
            : ios_(ios), sock_(ios), 
              t_(ios), email_(email), 
              l_(list), strand_(ios), 
              timeout_(timeout),
              stop_pending_(false)
    {
        // get rc host endpoint for this recipient
        union 
        {
            unsigned char bytes[sizeof uid];
            long long unsigned int lli;
        } uuid;

        uuid.lli = atol(uid.c_str());    
        ukeyh_ = djb2_hash(uuid.bytes, sizeof(uuid.bytes));
        int idx = (ukeyh_ % l_.size());
        lit_ = l_.begin() + idx;
        p_.ukey = uid;
        parse_email(email, p_.login, p_.domain);
        host_ = lit_->first;
    }

    void stop()
    {   
        stop_pending_ = true; 
        sock_.get_io_service().post( 
            strand_.wrap(bind(&rc_check::cancel, shared_from_this())));
    }

    inline const rc_parameters& get_parameters() const 
    {   return p_;   }

    inline const std::string& get_hostname() const
    {   return host_;   }

    const std::string& get_email() const 
    {   return email_;  }

    template <class Handler>
    void get(Handler handler)
    {
        int idx = (ukeyh_ % l_.size());
        lit_ = l_.begin() + idx;

        boost::shared_ptr<request<Handler> > req(new request<Handler>(handler, GET, shared_from_this()));
        get_helper(req, 0);
    }

    template <class Handler>
    void put(Handler handler, int size)
    {
        int idx = (ukeyh_ % l_.size());
        lit_ = l_.begin() + idx;

        p_.size = boost::lexical_cast<std::string>(size);
        boost::shared_ptr<request<Handler> > req(new request<Handler>(handler, PUT, shared_from_this()));
        put_helper(req, 0);
    }
};


#endif //RC_CHECK_H

