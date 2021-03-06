#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <vector>
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind/protect.hpp>
#include <boost/optional.hpp>
#include <boost/range.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio/detail/mutex.hpp>
#include <fstream>
#include <iostream>
#include "socket_pool_service.h"
#include "ylog.h"

using namespace std;
using namespace ylog;

struct client_parameters
{
    int tcnt; // num of threads
    int conseq;
    int concur;
    int port;
    std::string host;
    std::vector<std::string> filenames;
    std::vector<std::string> recipients;
};

struct state
{
    typedef boost::asio::ip::tcp::socket socket_type;
    typedef socket_type::endpoint_type endpoint_type;

    state(boost::asio::io_service& ios, int req, const client_parameters& p)
            : s_(ios),
              strand_(ios),
              req_(req),
              p_(p),
              starttm_(boost::posix_time::microsec_clock::local_time())
    {
        boost::mutex::scoped_lock lock(nmutex);
        num_ = ++nbase;
    }
    socket_type s_;
    boost::asio::io_service::strand strand_;
    boost::asio::streambuf buf_;
    int req_; // requests left
    client_parameters p_;
    int num_;
    int rcpts_pending_;
    boost::posix_time::ptime starttm_;
    static int nbase;
    static boost::mutex nmutex;
};

inline ylog_t::helper logw(const boost::shared_ptr<state>& st)
{   return ycout << "[" << st->num_ << "]:\t" <<
            boost::posix_time::microsec_clock::local_time() - st->starttm_ << ":\t>>\t"; }

inline ylog_t::helper logr(const boost::shared_ptr<state>& st)
{   return ycout << "[" << st->num_ << "]:\t" <<
            boost::posix_time::microsec_clock::local_time() - st->starttm_ << ":\t<<\t"; }

inline ylog_t::helper logrerr(const boost::shared_ptr<state>& st)
{   return ycout << "[" << st->num_ << "]:\t"
                 << boost::posix_time::microsec_clock::local_time() - st->starttm_ << ":\t(!)\tread error:"; }

inline ylog_t::helper logwerr(const boost::shared_ptr<state>& st)
{   return ycout << "[" << st->num_ << "]:\t"
                 << boost::posix_time::microsec_clock::local_time() - st->starttm_ << ":\t(!)\twrite error:"; }

inline ylog_t::helper logstat(const boost::shared_ptr<state>& st)
{   return ycout << "[" << st->num_ << "]:\t"
                 << boost::posix_time::microsec_clock::local_time() - st->starttm_ << ":\t(*)\t"; }

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

int state::nbase = 0;
boost::mutex state::nmutex;

template <class Handle>
void start_send_message(boost::shared_ptr<state> st, Handle h);

template <class Handle>
void try_again(boost::shared_ptr<state>& st, Handle h)
{
    if (--st->req_ > 0)
        start_send_message<Handle>(st, h);
    else
        st->s_.get_io_service().post(boost::bind(h, st));
    return;
}

template <class Handle>
struct handle_read_message
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logrerr(st) << ec;
            return try_again(st, h);
        }
        typedef boost::asio::streambuf::const_buffers_type const_buffers_type;
        typedef boost::asio::buffers_iterator<const_buffers_type> iterator;
        const_buffers_type buffers = st->buf_.data();
        iterator begin = iterator::begin(buffers);
        iterator end = iterator::end(buffers);

        logr(st) << boost::make_iterator_range(begin, end);
        st->buf_.consume(sz);

        // we're done;
        try {
            if ((g_rnd() % 5) == 0)
                st->s_.close();
        } catch (...) {}
        return try_again(st, h);
    }
};

template <class Handle>
struct handle_write_message
{
    boost::shared_ptr<state> st;
    Handle h;
    typedef boost::array<char, 4096> block_t;
    typedef boost::shared_ptr<std::pair<std::ifstream, block_t > > d_t;
    d_t d;

    bool step()
    {
        ifstream& fs = d->first;
        block_t& b = d->second;
        if (fs && !fs.eof())
        {
            int sz = 1+ g_rnd() % (b.size()-1); // bytes to write to the server
            fs.read(b.data(), sz);
            sz = fs.gcount();
            logw(st) << boost::iterator_range<const char*>(b.data(), b.data() + sz);
            boost::asio::async_write(st->s_, boost::asio::buffer(b.data(), sz), st->strand_.wrap(*this));
            return true; // there's more to send
        }
        // send ending token
        const char* phrase = "\r\n.\r\n";
        logw(st) << phrase;
        d.reset(); // use as completion token
        boost::asio::async_write(st->s_, boost::asio::buffer(phrase), st->strand_.wrap(*this));
        return false;
    }

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logwerr(st) << ec;
            return try_again(st, h);
        }
        if ( d && !step() )
        {
            handle_read_message<Handle> handle = { st, h };
            boost::asio::async_read_until(st->s_, st->buf_, std::string("\r\n"), st->strand_.wrap(handle));
        }
    }
};

template <class Handle>
struct handle_read_data
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logrerr(st) << ec;
            return try_again(st, h);
        }
        typedef boost::asio::streambuf::const_buffers_type const_buffers_type;
        typedef boost::asio::buffers_iterator<const_buffers_type> iterator;
        const_buffers_type buffers = st->buf_.data();
        iterator begin = iterator::begin(buffers);
        iterator end = iterator::end(buffers);

        // Look for 354 ..
        boost::iterator_range<const char*> delim = boost::as_literal("354 ");
        bool done = boost::starts_with(boost::make_iterator_range(begin, end), delim);

        logr(st) << boost::make_iterator_range(begin, end);
        st->buf_.consume(sz);

        if (!done)
            logrerr(st) << "bad response to data command";

        if (done && st->p_.filenames.size() > 0)
        {
            // Start sending a message
            size_t maxidx = st->p_.filenames.size();
            std::vector<std::string>::const_iterator fname_it = st->p_.filenames.begin() + (g_rnd() % maxidx);
            typedef typename handle_write_message<Handle>::block_t block_t;
            typedef typename handle_write_message<Handle>::d_t d_t;
            handle_write_message<Handle> handle = { st, h, d_t() };
            handle.d.reset( new std::pair<std::ifstream, block_t> );
            handle.d->first.open( fname_it->c_str() );
            handle.step();
        }
        else
        {
            return try_again(st, h);
        }
    }
};

template <class Handle>
struct handle_write_data
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logwerr(st) << ec.message();
            return try_again(st, h);
        }

        handle_read_data<Handle> handle = { st, h };
        boost::asio::async_read_until(st->s_, st->buf_, std::string("\r\n"), st->strand_.wrap(handle));
    }
};

template <class Handle>
struct send_rcpto_series;

template <class Handle>
struct handle_read_rcptto
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logrerr(st) << ec;
            return try_again(st, h);
        }
        typedef boost::asio::streambuf::const_buffers_type const_buffers_type;
        typedef boost::asio::buffers_iterator<const_buffers_type> iterator;
        const_buffers_type buffers = st->buf_.data();
        iterator begin = iterator::begin(buffers);
        iterator end = iterator::end(buffers);

        // Look for 250 ..
        boost::iterator_range<const char*> delim = boost::as_literal("250 ");
        bool done = boost::starts_with(boost::make_iterator_range(begin, end), delim);

        logr(st) << boost::make_iterator_range(begin, end);
        st->buf_.consume(sz);

        if (done)
        {
            if ( --st->rcpts_pending_ == 0 )
            {
                // we're done with RCPT TO
                handle_write_data<Handle> handle = { st, h };
                const char* phrase = "data \r\n";
                logw(st) << phrase;
                st->s_.async_write_some(boost::asio::buffer(phrase), st->strand_.wrap(handle));
            }
            else
            {
                // generate another RCPT TO
                send_rcpto_series<Handle> handle = { st, h };
                handle();
            }
        }
        else
        {
            logrerr(st) << "bad response to rcpt to";
            return try_again(st, h);
        }
    }
};


template <class Handle>
struct handle_write_rcptto
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logwerr(st) << ec.message();
            return try_again(st, h);
        }

        handle_read_rcptto<Handle> handle = { st, h };
        boost::asio::async_read_until(st->s_, st->buf_, std::string("\r\n"), st->strand_.wrap(handle));
    }
};

template <class Handle>
struct send_rcpto_series
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()()
    {
        size_t maxidx = st->p_.recipients.size();
        const char* phrase = (st->p_.recipients.begin() + (g_rnd() % maxidx))->c_str();

        handle_write_rcptto<Handle> handle = { st, h };
        logw(st) << phrase;
        st->s_.async_write_some(boost::asio::buffer(phrase), st->strand_.wrap(handle));
    }
};

template <class Handle>
struct handle_read_mailfrom
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logrerr(st) << ec.message();
            return try_again(st, h);
        }
        typedef boost::asio::streambuf::const_buffers_type const_buffers_type;
        typedef boost::asio::buffers_iterator<const_buffers_type> iterator;
        const_buffers_type buffers = st->buf_.data();
        iterator begin = iterator::begin(buffers);
        iterator end = iterator::end(buffers);

        // Look for 250 ..
        boost::iterator_range<const char*> delim = boost::as_literal("250 ");
        bool done = boost::starts_with(boost::make_iterator_range(begin, end), delim);

        logr(st) << boost::make_iterator_range(begin, end);
        st->buf_.consume(sz);

        if (done)
        {
            // we're done with MAIL FROM response
            st->rcpts_pending_ = 1 + (g_rnd() % st->p_.recipients.size());
            send_rcpto_series<Handle> handle = { st, h };
            handle();
        }
        else
        {
            logrerr(st) << "bad response to mail from";
            return try_again(st, h);
        }
    }
};

template <class Handle>
struct handle_write_mailfrom
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logwerr(st) << ec.message();
            return try_again(st, h);
        }

        handle_read_mailfrom<Handle> handle = { st, h };
        boost::asio::async_read_until(st->s_, st->buf_, std::string("\r\n"), st->strand_.wrap(handle));
    }
};

template <class Handle>
struct handle_read_ehlo
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logrerr(st) << ec.message();
            return try_again(st, h);
        }
        typedef boost::asio::streambuf::const_buffers_type const_buffers_type;
        typedef boost::asio::buffers_iterator<const_buffers_type> iterator;
        const_buffers_type buffers = st->buf_.data();
        iterator begin = iterator::begin(buffers);
        iterator end = iterator::end(buffers);

        // Look for \r\n
        boost::iterator_range<const char*> crlf = boost::as_literal("\r\n");
        boost::iterator_range<iterator> response(begin, end);
        end = boost::find_first(response, crlf).end();

        // Look for 250 ..
        boost::iterator_range<const char*> delim = boost::as_literal("250 ");
        bool done = boost::starts_with(boost::make_iterator_range(begin, end), delim);

        logr(st) << boost::make_iterator_range(begin, end);
        st->buf_.consume(end - begin);

        if (done)
        {
            // we're done with EHLO response
            handle_write_mailfrom<Handle> handle = { st, h };
            const char* phrase = "mail from: <testuser20@ya.ru>\r\n";
            logw(st) << phrase;
            st->s_.async_write_some(boost::asio::buffer(phrase), st->strand_.wrap(handle));
        }
        else
        {
            handle_read_ehlo<Handle> handle = { st, h };
            boost::asio::async_read_until(st->s_, st->buf_, std::string("\r\n"), st->strand_.wrap(handle));
        }
    }
};

template <class Handle>
struct handle_write_ehlo
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec, size_t sz)
    {
        if (ec)
        {
            logwerr(st) << ec.message();
            return try_again(st, h);
        }

        handle_read_ehlo<Handle> handle = { st, h };
        boost::asio::async_read_until(st->s_, st->buf_, std::string("\r\n"), st->strand_.wrap(handle));
    }
};

template <class Handle>
struct handle_connect
{
    boost::shared_ptr<state> st;
    Handle h;

    void operator()(const boost::system::error_code& ec)
    {
        if (ec)
        {
            logrerr(st) << " error connecting:" << ec.message();
            if (ec != boost::asio::error::already_connected)
                return try_again(st, h);
        }
        logstat(st) << "connected";
        handle_write_ehlo<Handle> handle = {st, h};
        const char* phrase = "EHLO ctor\r\n";
        logw(st) << phrase;
        st->s_.async_write_some(boost::asio::buffer(phrase), st->strand_.wrap(handle));
    }
};

template <class Handle>
void start_send_message(boost::shared_ptr<state> st, Handle h)
{
    state::endpoint_type endpoint(
        boost::asio::ip::address_v4::from_string(st->p_.host), st->p_.port);
    handle_connect<Handle> handle = {st, h};
    st->s_.async_connect(endpoint, handle);
}

template <class Handle>
void send_message(boost::asio::io_service& ios, const client_parameters& p, Handle h)
{
    boost::shared_ptr<state> st(new state(ios, p.conseq, p));
    start_send_message<Handle>(st, h);
}

void handle_send_message(boost::shared_ptr<state> st)
{
    logstat(st) << "done";
}

int main(int argc, char** argv)
{
    boost::asio::io_service ios;
    boost::shared_ptr<boost::asio::io_service::work> work(new boost::asio::io_service::work(ios));

    client_parameters p;

    boost::program_options::options_description cmd_opt("cmd line options");
    cmd_opt.add_options()
            ("help,h", "produce help message")
            ("port,p", boost::program_options::value<int>(&p.port)->default_value(1667), "remote port number")
            ("ip,i", boost::program_options::value<std::string>(&p.host)->default_value("127.0.0.1"), "remote host ip")
            ("threads,s", boost::program_options::value<int>(&p.tcnt)->default_value(10), "thread count")
            ("conseq,r", boost::program_options::value<int>(&p.conseq)->default_value(1), "number of consecutive requests")
            ("concur,c", boost::program_options::value<int>(&p.concur)->default_value(1), "number of concurrent invocations of conseq requests")
            ("input,f", boost::program_options::value<std::vector<std::string> >(&p.filenames), "filename containing a message to send")
            ("to,t", boost::program_options::value<std::vector<std::string> >(&p.recipients), "message recipient address")
            ;
    boost::program_options::variables_map vm;
    try
    {
        boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(cmd_opt).run(), vm);
        boost::program_options::notify(vm);
        if (vm.count("help") || !vm.count("to"))
        {
            ycout << cmd_opt;
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        cerr << "bad options: " << e.what();
        return -1;
    }

    boost::thread_group thr;
    for (int i=0; i< std::max(p.tcnt, 1); ++i)
        thr.create_thread(boost::bind(&boost::asio::io_service::run, &ios));

    boost::posix_time::ptime tm = boost::posix_time::microsec_clock::local_time();

    // for simplicity transform recipient addresses to corresponding smtp commands beforehand
    std::transform(p.recipients.begin(), p.recipients.end(),
            p.recipients.begin(), string("rcpt to:<") + boost::lambda::_1 + string(">\r\n"));

    for (int i=0; i< std::max(p.concur, 1); ++i)
        send_message(ios, p, handle_send_message);

    work.reset();

    thr.join_all();

    ycout << "time elapsed: " << boost::posix_time::microsec_clock::local_time()-tm;

    return 0;
}
