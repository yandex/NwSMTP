#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <string>
#include <boost/asio/buffer.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind/protect.hpp>
#include <boost/optional.hpp>
#include <boost/range.hpp>
#include <boost/array.hpp>
#include "socket_pool_service.h"
#include "ylog.h"

using namespace ylog;
using namespace std;

typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, 
                                         socket_pool_service<boost::asio::ip::tcp> > y_socket;

struct spool_parameters
{
    std::vector<boost::asio::ip::tcp::endpoint> endpoints;
    std::string request;
    int rpe; // number of consecutive requests per endpoint
    int crpe; // number of concurrent invocations of rpe consecutive requests
    int socktype;
};

template <class Socket>
void make_request(boost::asio::io_service& ios, const boost::asio::ip::tcp::endpoint& endpoint,
        const string& request, int rpe);

template <class Socket>
void handle_read(const boost::system::error_code& ec, std::size_t sz, const boost::asio::ip::tcp::endpoint& endpoint,
        const string& request, int rpe, boost::shared_ptr<Socket> socket, boost::shared_ptr<boost::asio::streambuf> buf)
{
    ycout << endpoint.address() << "<< \r\n" 
          << boost::make_iterator_range(boost::asio::buffers_begin(buf->data()),  boost::asio::buffers_begin(buf->data()) + sz)
          << "--";    
    make_request<Socket>(socket->get_io_service(), endpoint, request, rpe);
}


template <class Socket>
void handle_write(const boost::system::error_code& ec, const boost::asio::ip::tcp::endpoint& endpoint,
        const string& request, int rpe, boost::shared_ptr<Socket> socket)
{
    if (!ec)
    {
        //      ycout << ">>>" << endpoint.address();   
        boost::shared_ptr<boost::asio::streambuf> buf(new boost::asio::streambuf);
        boost::asio::async_read_until(*socket, *buf, std::string("\r\n0\r\n"),
                boost::protect(boost::bind(handle_read<Socket>, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred,
                                endpoint, request, rpe, socket, buf)));
    }
    else
    {   
        ycout << "error writing to " << endpoint;       
    }
}

template <class Socket>
void handle_connect(const boost::system::error_code& ec, const boost::asio::ip::tcp::endpoint& endpoint,
        const string& request, int rpe, boost::shared_ptr<Socket> socket)
{
    if (!ec)
    {
        socket->async_write_some(boost::asio::buffer(request), 
                boost::bind(handle_write<Socket>, boost::asio::placeholders::error,
                        endpoint, request, rpe, socket));
    }
    else
    {   
        ycout << "error connecting to " << endpoint;    
    }
}

template <class Socket>
void make_request(boost::asio::io_service& ios, const boost::asio::ip::tcp::endpoint& endpoint,
        const string& request, int rpe)
{
    if (rpe <= 0)
        return;
     
    boost::shared_ptr<Socket> socket (new Socket(ios));
    socket->async_connect(endpoint, boost::bind(handle_connect<Socket>, boost::asio::placeholders::error,
                    endpoint, request, --rpe, socket));
}

void start(boost::asio::io_service& ios, const spool_parameters& p)
{
    typedef std::vector<boost::asio::ip::tcp::endpoint> ev_t;    
    for (ev_t::const_iterator it=p.endpoints.begin(); it!=p.endpoints.end(); ++it)    
        for (int i=0; i<p.crpe; ++i)
            if (p.socktype == 0)
                make_request<boost::asio::ip::tcp::socket>(ios, *it, p.request, p.rpe);    
            else
                make_request<y_socket>(ios, *it, p.request, p.rpe);    
}

int main(int argc, char** argv)
{
    boost::asio::io_service ios;

    spool_parameters p;

    boost::program_options::options_description cmd_opt("cmd line options");
    cmd_opt.add_options()
            ("help,h", "produce help message")
            ("conseq,r", boost::program_options::value<int>(&p.rpe)->default_value(4), "number of consecutive requests per endpoint")
            ("concur,c", boost::program_options::value<int>(&p.crpe)->default_value(2), "number of concurrent invocations of conseq requests")
            ("type,t", boost::program_options::value<int>(&p.socktype)->default_value(1), "socket type to use (1: pooling socket, 0: basic socket")
            ;
    boost::program_options::variables_map vm;
    try 
    {   
        boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(cmd_opt).run(), vm);
        boost::program_options::notify(vm);
        if (vm.count("help"))
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


    boost::shared_ptr<boost::asio::io_service::work> work(new boost::asio::io_service::work(ios));

    boost::thread thread1(boost::bind(&boost::asio::io_service::run, &ios));   
    boost::thread thread2(boost::bind(&boost::asio::io_service::run, &ios));   

    boost::posix_time::ptime tm = boost::posix_time::microsec_clock::local_time();

    p.endpoints.push_back(boost::asio::ip::tcp::endpoint(
        boost::asio::ip::address_v4::from_string("77.88.46.178"), 8888));
    p.endpoints.push_back(boost::asio::ip::tcp::endpoint(
        boost::asio::ip::address_v4::from_string("77.88.61.18"), 8888));
    p.endpoints.push_back(boost::asio::ip::tcp::endpoint(
        boost::asio::ip::address_v4::from_string("95.108.131.33"), 8888));

    p.request = "GET /rc/get/52085780/Naf-Naff14/yandex.ru HTTP/1.1\r\n"
            "Accept: */*\r\n\r\n";

    start(ios, p);

    work.reset();
    
    thread1.join();
    thread2.join();

    cout << "time elapsed: " << boost::posix_time::microsec_clock::local_time()-tm << endl;

    return 0;
}
