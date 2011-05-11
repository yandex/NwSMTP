#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind/protect.hpp>
#include <boost/optional.hpp>
#include <boost/range.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio/detail/mutex.hpp>
#include "rc_check.h"
#include "ylog.h"

using namespace ylog;
using namespace std;

struct tormoz_parameters
{
    int tcnt;
    int rcnt;
    int rpe;
    string op;
    string host;
    int port;
    rc_parameters pp;
    rc_check::rclist l;
};

class tormoz_operation
{
  public:
    virtual ~tormoz_operation(){}
    virtual void justdoit() = 0;
};

class tormoz_get : public boost::enable_shared_from_this<tormoz_get>,
                   public tormoz_operation
{
    boost::asio::io_service& ios_;
    boost::asio::deadline_timer timer_;
    boost::asio::io_service::strand strand_;
    boost::shared_ptr<rc_check> rc_;
    const tormoz_parameters& p_;
    int count_;
    unsigned int seed_;
  public:
    tormoz_get(boost::asio::io_service& ios, const tormoz_parameters& p)
            : ios_(ios),
              timer_(ios),
              strand_(ios),
              rc_(new rc_check(ios, std::string(p.pp.login).append("@").append(p.pp.domain), p.pp.ukey, p.l, 1)),
              p_(p),
              count_(p.rpe)
    {
    }

    void handle_timeout(const boost::system::error_code& ec)
    {
        if (--count_ > 0)
        {
            rc_->stop();
            rc_.reset( new rc_check(timer_.io_service(), std::string(p_.pp.login).append("@").append(p_.pp.domain),
                            p_.pp.ukey, p_.l, 1) );

            timer_.expires_from_now(boost::posix_time::milliseconds(rand_r(&seed_) % 500));
            timer_.async_wait(strand_.wrap(boost::bind(&tormoz_get::handle_timeout, shared_from_this(), _1)));
        }
        else if (rc_)
        {
            rc_->stop();
            rc_.reset();
        }
    }

    void justdoit()
    {
        rc_->get(strand_.wrap(
            boost::bind(&tormoz_get::handle_done, shared_from_this(), _1, _2))
                 );
        timer_.expires_from_now(boost::posix_time::milliseconds(100));
        timer_.async_wait(strand_.wrap(boost::bind(&tormoz_get::handle_timeout, shared_from_this(), _1)));
    }

    void handle_done(const boost::system::error_code& ec, boost::optional<rc_result> rc)
    {
        if (rc)
        {
//             ycout << "get: [" <<
//                     p_.host << ":" << p_.port << " " <<
//                     p_.pp.ukey << ":" << p_.pp.login << ":" <<
//                     p_.pp.domain << " ] -> [" <<
//                     rc->ok << "," << rc->sum1 << "," <<
//                     rc->sum2 << "," << rc->sum3 << "," <<
//                     rc->sum4 << "]";
        }
        else
        {
//             ycout << "get: error:" << ec.message();
        }

        if (--count_ > 0)
            justdoit();
        else if (rc_)
        {
            rc_->stop();
            rc_.reset();
        }
    }
};

class tormoz_put : public boost::enable_shared_from_this<tormoz_put>,
                   public tormoz_operation
{
    boost::asio::io_service& ios_;
    boost::shared_ptr<rc_check> rc_;
    const tormoz_parameters& p_;
    int count_;
  public:
    tormoz_put(boost::asio::io_service& ios, const tormoz_parameters& p)
            : ios_(ios),
              rc_(new rc_check(ios, std::string(p.pp.login).append("@").append(p.pp.domain), p.pp.ukey, p.l, 1)),
              p_(p),
              count_(p.rpe)
    {}

    void justdoit()
    {
        rc_->put(boost::bind(
            &tormoz_put::handle_done, shared_from_this(), _1, _2),
                boost::lexical_cast<int>(p_.pp.size)
                 );
    }

    void handle_done(const boost::system::error_code& ec, boost::optional<rc_result> rc)
    {
        if (rc)
        {
            ycout << "put: [" <<
                    p_.host << ":" << p_.port << " " <<
                    p_.pp.ukey << ":" << p_.pp.login << ":" <<
                    p_.pp.domain << " ] -> [" <<
                    rc->ok << "," << rc->sum1 << "," <<
                    rc->sum2 << "," << rc->sum3 << "," <<
                    rc->sum4 << "]";
        }
        else
        {
            ycout << "put: error:" << ec.message();
        }

        if (--count_ > 0)
            justdoit();
    }
};


boost::shared_ptr<tormoz_operation> create_tormoz_operation(boost::asio::io_service& ios, const tormoz_parameters& p)
{
    using namespace boost;
    if (range::equal(as_literal(p.op), as_literal("get")))
        return shared_ptr<tormoz_operation>(new tormoz_get(ios, p));
    if (range::equal(as_literal(p.op), as_literal("put")))
        return shared_ptr<tormoz_operation>(new tormoz_put(ios, p));
    return shared_ptr<tormoz_operation>();
}

int main(int argc, char** argv)
{

    tormoz_parameters p;

    boost::asio::io_service ios;
    boost::shared_ptr<boost::asio::io_service::work> work(new boost::asio::io_service::work(ios));

    boost::program_options::options_description cmd_opt("cmd line options");
    cmd_opt.add_options()
            ("help,h", "produce help message")
            ("operation,o", boost::program_options::value<string>(&p.op)->default_value("get"), "type of operation")
            ("host,i", boost::program_options::value<string>(&p.host)->default_value("77.88.46.178"), "tormoz host")
            ("port,p", boost::program_options::value<int>(&p.port)->default_value(8888), "tormoz port")
            ("size,z", boost::program_options::value<string>(&p.pp.size)->default_value("0"), "put size (for put)")
            ("key,k", boost::program_options::value<string>(&p.pp.ukey)->default_value("0"), "user key")
            ("login,l", boost::program_options::value<string>(&p.pp.login)->default_value("testuser20"), "user login")
            ("domain,d", boost::program_options::value<string>(&p.pp.domain)->default_value("ya.ru"), "user domain")
            ("threads,s", boost::program_options::value<int>(&p.tcnt)->default_value(2), "thread count")
            ("conseq,r", boost::program_options::value<int>(&p.rpe)->default_value(1), "number of consecutive requests per endpoint")
            ("concur,c", boost::program_options::value<int>(&p.rcnt)->default_value(1), "number of concurrent invocations of conseq requests")
            ;
    boost::program_options::variables_map vm;
    try
    {
        boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(cmd_opt).run(), vm);
        boost::program_options::notify(vm);
        if (vm.count("help")
                || !vm.count("host") || !vm.count("port")
                || !vm.count("key") || !vm.count("login")
                || !vm.count("domain") )
        {
            cout << cmd_opt << endl;
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        cerr << "bad options: " << e.what() << endl;
        return -1;
    }

    p.l.push_back(
        std::make_pair(p.host,
                boost::asio::ip::tcp::endpoint(
                    boost::asio::ip::address_v4::from_string(p.host),
                    p.port)
                       )
        );

    boost::thread_group thr;
    for (int i=0; i< std::max(p.tcnt, 1); ++i)
        thr.create_thread(boost::bind(&boost::asio::io_service::run, &ios));

    boost::posix_time::ptime tm = boost::posix_time::microsec_clock::local_time();

    for (int i=0; i< std::max(p.rcnt, 1); ++i)
        create_tormoz_operation(ios, p)->justdoit();

    work.reset();

    thr.join_all();

    cout << "time elapsed: " << boost::posix_time::microsec_clock::local_time()-tm << endl;

    return 0;
}
