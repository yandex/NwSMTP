#include <boost/program_options.hpp>
#include <net/dns_resolver.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/asio/detail/mutex.hpp>

using namespace std;
using namespace y::net;

struct resolv_parameters
{
    resolv_parameters()
            : type(0),
              tcnt(2),
              rcnt(1)
    {}
    int type;
    int tcnt;
    int rcnt;
};


class resolver
{
  public:
    virtual void resolve(string)=0;
    virtual ~resolver() {} // just to stop gcc complaining
};

boost::asio::detail::mutex mutex_;

class resolver0 : public boost::enable_shared_from_this<resolver0>,
                  public resolver
{
    boost::asio::ip::tcp::resolver r_;

    void handle_resolve(string host, const boost::system::error_code& e, boost::asio::ip::tcp::resolver::iterator it)
    {
        boost::asio::detail::mutex::scoped_lock lock(mutex_);
        if (!e)
        {
            for ( ; it != boost::asio::ip::tcp::resolver::iterator() ; ++it)
                std::cout << host << " >> " << it->endpoint().address().to_string() << std::endl;
        }
        else
        {
            std::cout << host <<  " >> unknown" << std::endl;
        }
    }

  public:
    explicit resolver0(boost::asio::io_service& ios)
            : r_(ios)
    {}

    void resolve(string host)
    {
        boost::asio::detail::mutex::scoped_lock lock(mutex_);
        r_.async_resolve(boost::asio::ip::tcp::resolver::query(host, ""),
                boost::bind(&resolver0::handle_resolve, shared_from_this(), host,
                        boost::asio::placeholders::error,
                        boost::asio::placeholders::iterator));
    }
};


class resolver1 : public boost::enable_shared_from_this<resolver1>,
                  public resolver
{
    dns::resolver r_;
    boost::asio::strand strand_;
    static int count_;

    void handle_resolve(string host, const boost::system::error_code& e, dns::resolver::iterator it)
    {
        boost::asio::detail::mutex::scoped_lock lock(mutex_);
        count_++;
        if (!e)
        {
            for ( ; it != dns::resolver::iterator(); ++it)
                if (const boost::shared_ptr<dns::a_resource> ar = boost::dynamic_pointer_cast<dns::a_resource>(*it))
                    std::cout << host << " >> " << ar->address().to_string() << " [" << count_ << "]" << std::endl;
            return;
        }
        std::cout << host <<  " >> unknown [" << count_ << "]"  << std::endl;
    }

  public:
    explicit resolver1(boost::asio::io_service& ios)
            : r_(ios),
              strand_(ios)
    {
    }

    void resolve(string host)
    {
        boost::asio::detail::mutex::scoped_lock lock(mutex_);
        r_.async_resolve(host, dns::type_a,
                strand_.wrap(
                    bind(&resolver1::handle_resolve, shared_from_this(), host,
                            _1, _2))
                         );
    }
};
int resolver1::count_ = 0;

shared_ptr<resolver> create_resolver(boost::asio::io_service& ios, int type)
{
    if (type == 0)
        return shared_ptr<resolver>( new resolver0(ios) );
    else
        return shared_ptr<resolver>( new resolver1(ios) );
}


int main(int argc, char** argv)
{
    boost::asio::io_service ios;
    boost::shared_ptr<boost::asio::io_service::work> work(new boost::asio::io_service::work(ios));

    resolv_parameters p;

    boost::program_options::options_description cmd_opt("cmd line options");
    cmd_opt.add_options()
            ("help,h", "produce help message")
            ("type,t", boost::program_options::value<int>(&p.type)->default_value(0), "resolver type to use")
            ("threads,r", boost::program_options::value<int>(&p.tcnt)->default_value(2), "thread count")
            ("resolvers,s", boost::program_options::value<int>(&p.rcnt)->default_value(2), "resolver count")
            ;
    boost::program_options::variables_map vm;
    try
    {

        boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(cmd_opt).run(), vm);
        boost::program_options::notify(vm);
        if (vm.count("help"))
        {
            std::cout << cmd_opt << std::endl;
            return 1;
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "bad options: " << e.what() << std::endl;
        return -1;
    }

    boost::thread_group thr;
    for (int i=0; i< std::max(p.tcnt, 1); ++i)
        thr.create_thread(boost::bind(&boost::asio::io_service::run, &ios));

    std::vector<boost::shared_ptr<resolver> > resolvers;
    for (int i=0; i<std::max(p.rcnt, 1); ++i)
        resolvers.push_back(create_resolver(ios, p.type));

    string host;
    boost::posix_time::ptime tm = boost::posix_time::microsec_clock::local_time();

    std::vector<boost::shared_ptr<resolver> >::iterator resolver_it = resolvers.begin();
    while (getline(cin, host))
    {
        if (resolver_it == resolvers.end())
            resolver_it = resolvers.begin();

        if (!host.empty())
            ios.post( boost::bind(&resolver::resolve, *resolver_it++, host) );
    }

    work.reset();

    thr.join_all();
    resolvers.clear();

    std::cout << "test " << p.type << " :time elapsed: " << boost::posix_time::microsec_clock::local_time()-tm << std::endl;

    return 0;
}
