#ifndef YLOG_H_
#define YLOG_H_

#include <iostream>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

namespace ylog
{
using namespace std;

/// Helper class to allow output to cout with multiple threads
//---
struct ylog_t : private boost::noncopyable
{
    struct helper
    {
        ylog_t* q_;

        template <class T>
        helper& operator<< (const T& t)
        {
            q_->os_ << t;
            return *this;
        }

        helper(helper& rh)
                : q_(rh.q_)
        {
            rh.q_ = 0;
        }

        ~helper()
        {
            if (q_) {
                q_->os_ << endl;
                q_->m_.unlock();
            }
        }

      private:
        helper (ylog_t* y)
                : q_(y)
        {
            q_->m_.lock();
        }
        friend struct ylog_t;
    };

    std::ostream& os_;
    boost::mutex m_;

    explicit ylog_t(std::ostream& os)
            : os_(os)
    {
    }

    template <class T>
    ylog_t::helper operator<< (T t)
    {
        helper h (this);
        os_ << t;
        return h;
    }
};

extern ylog_t ycout;
extern ylog_t ycerr;

//---

} // namespace ylog

#endif // YLOG_H_

