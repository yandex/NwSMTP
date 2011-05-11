#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind/protect.hpp>
#include <boost/optional.hpp>

#include "aspf.h"

void handle_spf_check(spf_parameters p, boost::optional<string> result, boost::optional<string> expl)
{
    std::cout << "---" << p.domain << "---" << endl;
    if (result)
        cout << *result << endl;
    else
        cout << "(skip)" << endl;
    if (expl)
        cout << *expl << endl;
}

int main(int argc, char** argv)
{

    boost::asio::io_service ios;
    boost::shared_ptr<boost::asio::io_service::work> work(new boost::asio::io_service::work(ios));

    spf_parameters p;

    boost::program_options::options_description cmd_opt("cmd line options");
    cmd_opt.add_options()
            ("help,h", "produce help message")
            ("ip,i", boost::program_options::value<string>(&p.ip)->default_value("8.8.8.8"), "user ip")
            ("from,f", boost::program_options::value<string>(&p.from), "smtp from")
            ("domain,d", boost::program_options::value<string>(&p.domain), "smtp hello")
            ;
    boost::program_options::variables_map vm;
    try
    {
        boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(cmd_opt).run(), vm);
        boost::program_options::notify(vm);
        if (vm.count("help") /*|| !vm.count("domain") */)
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

    boost::thread thread1(boost::bind(&boost::asio::io_service::run, &ios));
    boost::thread thread2(boost::bind(&boost::asio::io_service::run, &ios));

    boost::posix_time::ptime tm = boost::posix_time::microsec_clock::local_time();

    if (vm.count("domain") || vm.count("from"))
        async_check_SPF(ios, p, boost::protect(boost::bind(handle_spf_check, p, _1, _2)));
    else
    {
        string host;
        while (getline(cin, host))
        {
            if (!host.empty())
            {
                p.domain = host;
                async_check_SPF(ios, p, boost::protect(boost::bind(handle_spf_check, p, _1, _2)));
            }
        }
    }
    work.reset();

    thread1.join();
    thread2.join();

    cout << "time elapsed: " << boost::posix_time::microsec_clock::local_time()-tm << endl;

    return 0;
}
