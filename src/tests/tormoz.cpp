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
#include "atormoz.h"
#include "socket_pool_service.h"
#include "ylog.h"

using namespace ylog;
using namespace std;

struct tormoz_parameters
{
    int socktype;
    int tcnt;
    int rcnt;    
    int rpe;
    string op;
    string host;
    int port;
    rc_parameters pp;
};

class tormoz_operation
{
  public:
    virtual ~tormoz_operation(){}
    virtual void justdoit() = 0;
};

template <class Socket>
class tormoz_get : public boost::enable_shared_from_this<tormoz_get<Socket> >,
                   public tormoz_operation
{
    boost::asio::io_service& ios_;
    Socket s_;
    const tormoz_parameters& p_;
    int count_;
  public:
    tormoz_get(boost::asio::io_service& ios, const tormoz_parameters& p)
            : ios_(ios),
              s_(ios),
              p_(p),
              count_(p.rpe)
    {}

    void justdoit() 
    {   
        typename Socket::endpoint_type endpoint(
            boost::asio::ip::address_v4::from_string(p_.host), p_.port);
        async_rc_get(s_, endpoint, p_.pp, 
                boost::protect(boost::bind(&tormoz_get::handle_done, 
                                this->shared_from_this(), _1, _2)));    
    }

    void handle_done(const boost::system::error_code& ec, boost::optional<rc_result> rc)
    {
        if (rc)
        {
            ycout << "get: [" <<
                    p_.host << ":" << p_.port << " " <<
                    p_.pp.ukey << ":" << p_.pp.login << ":" << 
                    p_.pp.domain << " ] -> [" <<
                    rc->ok << "," << rc->sum1 << "," << 
                    rc->sum2 << "," << rc->sum3 << "," << 
                    rc->sum4 << "]";
        }
        else
        {
            ycout << "get: error:" << ec.message();
        }

        try 
        {           
            s_.close();
        } 
        catch(...) {}

        if (--count_ > 0)
            justdoit();
    }
};

template <class Socket>
class tormoz_put : public boost::enable_shared_from_this<tormoz_put<Socket> >,
                   public tormoz_operation
{
    boost::asio::io_service& ios_;
    Socket s_;
    const tormoz_parameters& p_;
    int count_;
  public:
    tormoz_put(boost::asio::io_service& ios, const tormoz_parameters& p)
            : ios_(ios),
              s_(ios),
              p_(p),
              count_(p.rpe)
    {}

    void justdoit() 
    {   
        typename Socket::endpoint_type endpoint(
            boost::asio::ip::address_v4::from_string(p_.host), p_.port);
        async_rc_put(s_, endpoint, p_.pp, 
                boost::protect(boost::bind(&tormoz_put::handle_done, 
                                this->shared_from_this(), _1, _2)));    
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
            ycout << "put: error" << ec.message();
        }

        try 
        {
            s_.close();
        } 
        catch(...)
        {}

        if (--count_ > 0)
            justdoit();
    }
};

template <class Socket>
boost::shared_ptr<tormoz_operation> create_tormoz_operation_helper(boost::asio::io_service& ios, const tormoz_parameters& p)
{
    using namespace boost;
    if (range::equal(as_literal(p.op), as_literal("get")))
        return shared_ptr<tormoz_operation>(new tormoz_get<Socket>(ios, p));
    if (range::equal(as_literal(p.op), as_literal("put")))
        return shared_ptr<tormoz_operation>(new tormoz_put<Socket>(ios, p));
    return shared_ptr<tormoz_operation>();
}

boost::shared_ptr<tormoz_operation> create_tormoz_operation(boost::asio::io_service& ios, const tormoz_parameters& p)
{
    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, 
            socket_pool_service<boost::asio::ip::tcp> > y_socket;
    
    if (p.socktype == 0)
        return create_tormoz_operation_helper<boost::asio::ip::tcp::socket>(ios, p);
    else
        return create_tormoz_operation_helper<y_socket>(ios, p);
}

int main(int argc, char** argv)
{

    tormoz_parameters p;

    boost::asio::io_service ios;
    boost::shared_ptr<boost::asio::io_service::work> work(new boost::asio::io_service::work(ios));

    boost::program_options::options_description cmd_opt("cmd line options");
    cmd_opt.add_options()
            ("help,h", "produce help message")
            ("type,t", boost::program_options::value<int>(&p.socktype)->default_value(1), "socket type to use (1: pooling socket, 0: basic socket")
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
        if (vm.count("help") || !vm.count("type") 
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
