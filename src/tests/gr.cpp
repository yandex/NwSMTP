#include <boost/enable_shared_from_this.hpp>
#include <fstream>
#include "basic_test.h"
#include "greylisting.h"
#include "buffers.h"
#include "header_parser.h"
#include "yield.hpp"

namespace ba = boost::asio;
namespace bpo = boost::program_options;

struct parameters : public t::basic_parameters
{
    typedef ystreambuf::const_buffers_type const_bufs_t;
    typedef ybuffers_iterator<const_bufs_t> const_bufs_iter_t;

    int min_delay;
    int max_delay;
    std::string config_filename;
    std::string message_filename;
    std::string env_from;
    std::string env_to;
    std::string client_ip;

    greylisting_options opt;
    greylisting_client::headers headers;
    boost::shared_ptr<greylisting_client::key> key;
    const_bufs_t const_bufs;
};

bool is_help_requested(bpo::variables_map vm, const parameters* p)
{
    return t::is_help_requested(vm, p)
            || !vm.count("conf")
            || !vm.count("message");
}

void add_options(bpo::options_description* descr, parameters* p)
{
    t::add_options(descr, p);

    descr->add_options()
            ("message,f", bpo::value<string>(&p->message_filename), "message filename")
            ("mindelay", bpo::value<int>(&p->min_delay)->default_value(0),
                    "min delay of a random interruption in milliseconds")
            ("maxdelay", bpo::value<int>(&p->max_delay)->default_value(0),
                    "max delay of a random interruption in milliseconds (set to 0 to disable interruption)")
            ("conf", bpo::value<string>(&p->config_filename), "greylisting config filename")
            ("env_from", bpo::value<string>(&p->env_from)->default_value("testuser20@ya.ru"), "smtp from")
            ("env_to", bpo::value<string>(&p->env_to)->default_value("testuser40@ya.ru"), "smtp to")
            ("client_ip", bpo::value<string>(&p->client_ip)->default_value("127.0.0.1"), "client ip")
            ;
}

void handle_parse_header(greylisting_client::headers* gr_headers,
        const header_iterator_range_t& name,
        const header_iterator_range_t& header,
        const header_iterator_range_t& value)
{
    string lname;
    size_t name_sz = name.size();
    lname.reserve(name_sz);
    std::transform(name.begin(), name.end(), back_inserter(lname), ::tolower);

    if ( !strcmp(lname.c_str(), "message-id") )
        gr_headers->messageid = value;
    else if ( !strcmp(lname.c_str(), "to") )
        gr_headers->to = value;
    else if ( !strcmp(lname.c_str(), "from") )
        gr_headers->from = value;
    else if ( !strcmp(lname.c_str(), "subject") )
        gr_headers->subject = value;
    else if ( !strcmp(lname.c_str(), "date") )
        gr_headers->date = value;
}

int parse_options(int argc, char** argv, parameters* p)
{
    if (int rval = t::parse_options(argc, argv, p))
        return rval;

    // Parse config file.
    try
    {
        greylisting_options_parser parser(p->opt);
        parser.parse_from_file(p->config_filename.c_str());
    }
    catch (const std::exception& e)
    {
        std::ostringstream err;
        err << "error processing config file \""
            << p->config_filename << "\": " << e.what();
        throw std::runtime_error(err.str());
    }

    // Parse message file.
    std::fstream f(p->message_filename.c_str());
    typedef greylisting_client::iter_range_t iter_range_t;
    typedef iter_range_t::const_iterator const_bufs_iter_t;

    boost::array<char, ystreambuf::chunk_size> buf;
    while (f)
    {
        f.read(buf.data(), buf.size());
        int sz = f.gcount();
        shared_mutable_chunk::container_ptr cont_ptr(
            new chunk_array<ystreambuf::chunk_size>(buf));
        append(shared_mutable_chunk(
            cont_ptr, cont_ptr->begin(),
            cont_ptr->begin() + sz), p->const_bufs);
    }

    const_bufs_iter_t bb = ybuffers_begin(p->const_bufs);
    const_bufs_iter_t ee = ybuffers_end(p->const_bufs);
    if (bb == ee)
    {
        std::cerr << "error processing message file \""
                  << p->message_filename
                  << "\": file is empty or does not exist";
        return -1;
    }

    const_bufs_iter_t body_beg =
            parse_header(
                header_iterator_range_t(bb, ee),
                boost::bind(&handle_parse_header, &p->headers, _1, _2, _3));
    p->key.reset(new greylisting_client::key(
        boost::asio::ip::address_v4::from_string(p->client_ip),
        p->env_from,
        p->env_to,
        p->headers,
        iter_range_t(body_beg, ee)));

    return 0;
}

class test : public t::test1<test, parameters>
{
    typedef t::test1<test, parameters> base;
    boost::shared_ptr<greylisting_client> d_;

  public:
    test(ba::io_service& ios, const parameters& p)
            : base(ios, p, p.min_delay, p.max_delay),
              d_( new greylisting_client(ios, p.opt, p.opt.hosts) )
    {
    }

    template <class Handler>
    struct handle_io : private coroutine
    {
        boost::shared_ptr<test> t;
        boost::shared_ptr<greylisting_client> d;
        Handler h;

        handle_io(boost::shared_ptr<test> tt,
                boost::shared_ptr<greylisting_client> dd,
                Handler hh)
                : t(tt),
                  d(dd),
                  h(hh)
        {
        }

        typedef boost::system::error_code error_code;
        typedef greylisting_client::hostlist hostlist;

        void operator()(const error_code& ec = error_code(),
                hostlist::value_type host = hostlist::value_type())
        {
            reenter(*this)
            for(;;)
            {
                yield d->probe(*t->p_.key, std::string("gr probing"), *this);
                if (ec != boost::asio::error::operation_aborted)
                    yield d->mark(std::string("gr marking: last probe status: ")
                            + ec.message(), *this);
                return h( ec, host );
            }
        }
    };

    template <class Handler>
    void do_start(Handler handler)
    {
        handle_io<Handler> h ( shared_from_this(), d_, handler );
        h();
    }

    void stop()
    {
        d_->stop();
    }

    template <typename H>
    friend class handle_io;
};

int main(int argc, char** argv)
{
    return t::main<test>(argc, argv);
}

