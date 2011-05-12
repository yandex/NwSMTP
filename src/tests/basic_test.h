#ifndef NWSMTP_BASIC_TEST_H
#define NWSMTP_BASIC_TEST_H

#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <iostream>

namespace t // we need to put this into a namespace to make ADL work for hooks
{

struct basic_parameters
{
    int tcnt;    // thread count
    int rcnt;    // number of concurrent invocations of conseq requests
    int rpe;     // number of consecutive requests per endpoint
};

template <class T, class P>
class test0 : public boost::enable_shared_from_this<T>
{
  public:
    typedef P parameters;

    static boost::shared_ptr<T> create_test(boost::asio::io_service& ios,
            const parameters& p)
    {
        return boost::shared_ptr<T>(new T(ios, p));
    }

    int count_;
  protected:
    boost::asio::io_service& ios_;
    const parameters& p_;

    test0(boost::asio::io_service& ios, const parameters& p)
            : count_(p.rpe),
              ios_(ios),
              p_(p)
    {
    }

    void restart()
    {
        if (--count_ > 0)
            static_cast<T*>(this)->start();
    }
};

template <class T, class P>
class test1 : public test0<T,P>
{
  protected:
    boost::asio::deadline_timer timer_;
    boost::asio::io_service::strand strand_;
    unsigned int seed_;
    int min_delay_;
    int max_delay_;

    test1(boost::asio::io_service& ios, const P& p, int min_delay, int max_delay)
            : test0<T,P>(ios, p),
              timer_(ios),
              strand_(ios),
              seed_(time(0)),
              min_delay_(std::min(min_delay, max_delay)),
              max_delay_(max_delay)
    {
    }

    void handle_timeout(const boost::system::error_code& ec)
    {
        if (ec == boost::asio::error::operation_aborted)
            return;

        T* that = static_cast<T*>(this);

        that->stop();

        that->restart();
    }

    void handle_done(const boost::system::error_code& ec)
    {
        if (ec == boost::asio::error::operation_aborted)
            return;

        T* that = static_cast<T*>(this);

        if (ec)
        {
            that->stop();
            timer_.cancel();
        }

        that->restart();
    }

  public:
    void start()
    {
        T* that = static_cast<T*>(this);

        that->do_start(strand_.wrap(
            boost::bind(&T::handle_done,
                    that->shared_from_this(), _1)));

        if (max_delay_ > 0)
        {
            boost::posix_time::time_duration expd =
                    boost::posix_time::milliseconds(
                        min_delay_ +
                        (min_delay_ == max_delay_
                                ? 0
                                : rand_r(&seed_) % (max_delay_ - min_delay_)))
                    ;
            timer_.expires_from_now(expd);
             timer_.async_wait(strand_.wrap(
                 boost::bind(&T::handle_timeout,
                         that->shared_from_this(), _1)));
        }
    }
};

template <class P>
bool is_help_requested(boost::program_options::variables_map vm, const P*)
{
    return vm.count("help") != 0;
}

template <class P>
void add_options(boost::program_options::options_description* descr, P* p)
{
    descr->add_options()
            ("help,h", "produce help message")
            ("threads,s", boost::program_options::value<int>(&p->tcnt)->default_value(2), "thread count")
            ("conseq,r", boost::program_options::value<int>(&p->rpe)->default_value(1), "number of consecutive requests per endpoint")
            ("concur,c", boost::program_options::value<int>(&p->rcnt)->default_value(1), "number of concurrent invocations of conseq requests")
            ;
}

template <class P>
int parse_options(int argc, char** argv, P* p)
{
    boost::program_options::options_description descr("Command line options");
    add_options(&descr, p);
    boost::program_options::variables_map vm;
    boost::program_options::store(
        boost::program_options::command_line_parser(argc,
                argv).options(descr).run(), vm);
    boost::program_options::notify(vm);
    if (is_help_requested(vm, p))
    {
        std::cout << descr << std::endl;
        return 1;
    }

    return 0;
}

template <class T>
int main(int argc, char** argv)
{
    typedef typename T::parameters parameters;

    boost::asio::io_service ios;
    boost::shared_ptr<boost::asio::io_service::work> work(
        new boost::asio::io_service::work(ios));

    parameters p;
    try
    {
        if (int po_rval = parse_options(argc, argv, &p))
            return po_rval;
    }
    catch (const std::exception& e)
    {
        std::cerr << "bad options: " << e.what() << std::endl;
        return -1;
    }

    boost::thread_group thr;
    for (int i=0; i< std::max(p.tcnt, 1); ++i)
        thr.create_thread(boost::bind(&boost::asio::io_service::run, &ios));

    boost::posix_time::ptime tm =
            boost::posix_time::microsec_clock::local_time();

    for (int i=0; i< std::max(p.rcnt, 1); ++i)
        T::create_test(ios, p)->start();

    work.reset();

    thr.join_all();

    std::cout << "time elapsed: "
              << boost::posix_time::microsec_clock::local_time() - tm
              << std::endl;

    return 0;
}

} // namespace t

#endif // NWSMTP_BASIC_TEST_H
