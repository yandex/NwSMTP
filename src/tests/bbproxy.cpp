#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/array.hpp>
#include <boost/regex.hpp>
#include <iostream>
#include <net/dns_resolver.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/regex.hpp>
#include "yield.hpp"

#include "ylog.h"
using namespace ylog;
using namespace y::net;

struct server_parameters
{
    int tcnt;
    int port;
    std::string bbhost;
    int bbport;
};

unsigned int gen_seed()
{
    return static_cast<unsigned int>(time(NULL));
}

class yrand
{
    unsigned int seed_;
    boost::mutex mux_;

  public: 
    explicit yrand(unsigned int seed = gen_seed())
            : seed_(seed)
    {}

    int operator()()
    {
        boost::mutex::scoped_lock lock(mux_);
        return rand_r(&seed_);
    }
} g_rnd;

class connection;
typedef boost::shared_ptr<connection> connection_ptr;

class connection: public boost::enable_shared_from_this<connection>,
                  private boost::noncopyable,
                  private coroutine
{
    boost::asio::ip::tcp::socket s_;
    boost::asio::ip::tcp::socket bb_s_;
    dns::resolver resolver_;
    boost::asio::io_service::strand strand_;
    boost::asio::deadline_timer timer_;
    boost::asio::deadline_timer timer2_;
    boost::asio::streambuf buf_;
    std::string bbhost_;
    int bbport_;
    std::list<boost::asio::const_buffer> mod_request_;

    struct handle_io
    {
        typedef void result_type;
        connection_ptr conn_;
        void operator()(const boost::system::error_code& ec, size_t sz);
    };
    friend struct handle_io;

    void handle_hangup_timer(const boost::system::error_code& ec)
    {   
        if (ec != boost::asio::error::operation_aborted)
            stop();
    }

    void start_hangup_timer()
    {   
        timer_.expires_from_now(boost::posix_time::milliseconds( g_rnd() % 3000 ));
        timer_.async_wait(
            boost::bind(&connection::handle_hangup_timer, 
                    shared_from_this(), boost::asio::placeholders::error));
    }

    void handle_resolve(const boost::system::error_code& ec, dns::resolver::iterator it)
    {
        if (!ec)
        {
            boost::asio::ip::tcp::endpoint endpoint(
                boost::dynamic_pointer_cast<dns::a_resource>(*it)->address(), bbport_);
            handle_io handler = { shared_from_this() };
            bb_s_.async_connect(endpoint, boost::bind(handler, _1, 0));
            return;
        }       
        ycout << "resolve failed: " << ec.message();
    }
    
    void do_stop()
    {
        try {
            s_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            s_.close();
            bb_s_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            bb_s_.close();
        } catch(...) {}
    }

  public:
    explicit connection(boost::asio::io_service& ios, const std::string& bbhost, int bbport)
            : s_(ios),
              bb_s_(ios),
              resolver_(ios),
              strand_(ios),
              timer_(ios),
              timer2_(ios),
              bbhost_(bbhost),
              bbport_(bbport)
    {}

    ~connection()
    {
        ycout << "closing connection";
        do_stop();
    }

    boost::asio::ip::tcp::socket& socket()
    {   return s_;   }

    void start()
    {
        resolver_.async_resolve(bbhost_,
                dns::type_a,
                strand_.wrap(boost::bind(&connection::handle_resolve, 
                                shared_from_this(), boost::asio::placeholders::error,
                                boost::asio::placeholders::iterator)));        
    }

    void stop()
    {
        s_.get_io_service().post(strand_.wrap(boost::bind(&connection::do_stop, shared_from_this())));
    }
};

void connection::handle_io::operator()(const boost::system::error_code& ec, size_t sz)
{
    typedef boost::asio::streambuf::const_buffers_type const_buffers_type;
    typedef boost::asio::buffers_iterator<const_buffers_type> iterator;
    boost::iterator_range<iterator> host_line_prefix;    

    reenter (*conn_)
    {   
        if (!ec)
            ycout << "connected to bb server: " << conn_->bbhost_ << ":" << conn_->bbport_;
        else
        {
            ycout << "failed to connect to bb server: " << conn_->bbhost_ << ":" << conn_->bbport_;
            return;
        }

        if ((g_rnd() % 2) == 0)
            conn_->start_hangup_timer(); // start timer that emulates network problems (hangups randomly)

        yield async_read_until(conn_->s_, 
                conn_->buf_, boost::regex("\n\r?\n"), conn_->strand_.wrap(*this));

        if (ec && ec != boost::asio::error::eof)
        {
            ycout << "failed to read request: " << ec.message();
            return;
        }

        host_line_prefix = boost::make_iterator_range(iterator::begin(conn_->buf_.data()),
                iterator::begin(conn_->buf_.data()));
        
        while (host_line_prefix.end() != iterator::end(conn_->buf_.data()))
        {
            boost::iterator_range<iterator> input = 
                    boost::make_iterator_range(
                        host_line_prefix.end(), iterator::end(conn_->buf_.data()));
            boost::iterator_range<iterator> line = 
                    boost::find_first(input, "\n");     
                   
            // Look for Host: ..
            if ( boost::istarts_with(boost::make_iterator_range(
                    host_line_prefix.end(), line.end()), "Host:"))          
                break;      
            host_line_prefix = boost::make_iterator_range(host_line_prefix.begin(), line.end());
        }

        if (host_line_prefix.end() == iterator::end(conn_->buf_.data()))
        {
            // No Host:. Send the request as is.
            yield conn_->bb_s_.async_write_some(conn_->buf_.data(), 
                    conn_->strand_.wrap(*this));

            if (ec)
            {
                ycout << "failed to redirect response: " << ec.message();
                return;
            }

            conn_->buf_.consume(sz);        
        }
        else
        {              
            yield conn_->bb_s_.async_write_some(boost::asio::buffer(conn_->buf_.data() + 
                            (host_line_prefix.begin() - iterator::begin(conn_->buf_.data())),
                            host_line_prefix.end() - host_line_prefix.begin()),
                    conn_->strand_.wrap(*this));
            conn_->buf_.consume(sz);

            // Substite Host: with a real hostname
            conn_->mod_request_.push_back(boost::asio::const_buffer("Host: ", 6));
            conn_->mod_request_.push_back(boost::asio::buffer(conn_->bbhost_));
            conn_->mod_request_.push_back(boost::asio::const_buffer("\r\n", 2));
            if (!ec)
                yield conn_->bb_s_.async_write_some(conn_->mod_request_,
                        conn_->strand_.wrap(*this));

            // Send the rest of the request
            if (!ec)
            {
                boost::iterator_range<iterator> input = 
                        boost::make_iterator_range(
                            iterator::begin(conn_->buf_.data()), iterator::end(conn_->buf_.data()));            
                boost::iterator_range<iterator> line = 
                        boost::find_first(input, "\n"); 
                conn_->buf_.consume(line.end() - host_line_prefix.end());
            }

            if (!ec)
            {
                yield conn_->bb_s_.async_write_some(conn_->buf_.data(),
                        conn_->strand_.wrap(*this));
                conn_->buf_.consume(sz);                
            }
            

            if (ec)
            {
                ycout << "failed to redirect response: " << ec.message();
                return;
            }
        }

        while (!ec)
        {
            yield async_read_until(conn_->bb_s_, 
                    conn_->buf_, std::string("\n"), conn_->strand_.wrap(*this));     

            if (ec && ec != boost::asio::error::eof)
            {
                ycout << "failed to read response: " << ec.message();
                return;
            }

            if (ec == boost::asio::error::eof)
            {
                yield conn_->s_.async_write_some(conn_->buf_.data(), 
                        conn_->strand_.wrap(*this));
                return;
            }

            while (!ec && conn_->buf_.size() > 0)
            {
                // start another timer that emulates network problems (lags randomly)
                if ((g_rnd() % 17) == 0)
                {
                    conn_->timer2_.expires_from_now(boost::posix_time::milliseconds( g_rnd() % 300 ));    
                    yield conn_->timer2_.async_wait(
                        conn_->strand_.wrap(boost::bind(*this, boost::asio::placeholders::error, 0)));
                }

                yield async_write(conn_->s_, boost::asio::buffer(conn_->buf_.data(), 1+g_rnd() % 10), 
                        conn_->strand_.wrap(*this));
                conn_->buf_.consume(sz);
            }

            return;
        }       
    }
}


class server
{
    boost::asio::ip::tcp::acceptor acceptor_;
    connection_ptr connection_;
    server_parameters p_;

    void handle_accept(const boost::system::error_code& ec)
    {
        if (!ec)
        {
            connection_ptr conn = connection_;

            connection_.reset( new connection(acceptor_.get_io_service(), p_.bbhost, p_.bbport) );
            acceptor_.async_accept(connection_->socket(),
                    boost::bind(&server::handle_accept, this,
                            boost::asio::placeholders::error));

            conn->start();
            return;
        }
        std::cout << "accept failed! BYE!" << std::endl;
    }

  public:
    explicit server(boost::asio::io_service& ios, const server_parameters& p)
            : acceptor_(ios),
              p_(p)
    {
    }

    void run()
    {
        connection_.reset( new connection(acceptor_.get_io_service(), p_.bbhost, p_.bbport) );

        // Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::address_v4::from_string("127.0.0.1"), p_.port);    

        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
        acceptor_.async_accept(connection_->socket(),
                boost::bind(&server::handle_accept, this,
                        boost::asio::placeholders::error));
    }    

    void stop();
};

int main(int argc, char** argv)
{
    boost::asio::io_service ios;
    boost::shared_ptr<boost::asio::io_service::work> work(new boost::asio::io_service::work(ios));
 
    server_parameters p;

    boost::program_options::options_description cmd_opt("cmd line options");
    cmd_opt.add_options()
            ("help,h", "produce help message")
            ("port,p", boost::program_options::value<int>(&p.port)->default_value(8080), "local port number")
            ("bbport,b", boost::program_options::value<int>(&p.bbport)->default_value(80), "bb port number")
            ("bbhost,d", boost::program_options::value<std::string>(&p.bbhost)->default_value("blackbox-mimino.yandex.net"), "bb host")
            ("threads,s", boost::program_options::value<int>(&p.tcnt)->default_value(10), "thread count")
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
    catch (const std::exception& e)
    {
        std::cerr << "bad options: " << e.what() << std::endl;
        return -1;
    }

    boost::thread_group thr;
    for (int i=0; i< std::max(p.tcnt, 1); ++i)
        thr.create_thread(boost::bind(&boost::asio::io_service::run, &ios));
    

    server s(ios, p);
    s.run();

    work.reset();
    
    thr.join_all();

    return 0;
}
