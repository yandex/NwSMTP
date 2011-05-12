#include <boost/functional/hash.hpp>
#include <boost/thread.hpp>
#include <boost/lexical_cast.hpp>
#include <sys/types.h> // for getpid
#include <unistd.h>
#include "greylisting.h"


// --
class basic_gr_category_t : public boost::system::error_category
{
  public:
    const char* name() const
    {
        return "nwsmtp.gr";
    }

    std::string message(int value) const
    {
        if (value == greylisting_client::too_early)
            return "Too early";
        if (value == greylisting_client::too_late)
            return "Too late";
        if (value == greylisting_client::logical_error)
            return "Logical error (e.g. mark() called before probe())";
        return "nwsmtp.gr error";
    }
};

const boost::system::error_category& get_gr_category()
{
    static basic_gr_category_t instance;
    return instance;
}

namespace boost
{
template <class Range>
std::size_t hash_value(const Range& r)
{
    return boost::hash_range(r.begin(), r.end());
}
}

std::size_t hash_value(const greylisting_client::key& i, const greylisting_options& opt)
{
    std::size_t seed = 0;
    if (opt.use_ip)
        boost::hash_combine(seed, i.client_ip.to_string());
    if (opt.use_envelope_from)
        boost::hash_combine(seed, i.envelope_from);
    if (opt.use_envelope_to)
        boost::hash_combine(seed, i.envelope_to);
    if (opt.use_header_from)
        boost::hash_combine(seed, i.h.from);
    if (opt.use_header_to)
        boost::hash_combine(seed, i.h.to);
    if (opt.use_header_messageid)
        boost::hash_combine(seed, i.h.messageid);
    if (opt.use_header_subject)
        boost::hash_combine(seed, i.h.subject);
    if (opt.use_header_date)
        boost::hash_combine(seed, i.h.date);
    if (opt.use_body)
    {
        // Compute normalised body hash
        typedef greylisting_client::iter_range_t iter_range_t;
        iter_range_t::const_iterator bb = i.body.begin();
        iter_range_t::const_iterator ee = i.body.end();
        iter_range_t::const_iterator pp = bb;

        bool cr = false;
        bool lf = false;
        while (pp != ee)
        {
            const char* b0 = &*bb;
            const char* p0 = &*pp;
            const char* b = b0;
            const char* p = p0;
            const char* e = ptr_end(pp, ee);

            while (p != e)
            {
                if (p != e && lf && *p == '.')
                {
                    assert(b == p);
                    b = ++p;
                    lf = false;
                }

                while (p != e && *p != '\n' && *p != '\r')
                    ++p;
                if (p == e)
                {
                    boost::hash_combine(seed, boost::make_iterator_range(b, p));
                    b = p;
                    break;
                }
                else if (*p == '\r')
                {
                    p++;
                    cr = true;
                    lf = false;
                }
                else if (cr) // '*\r\n'
                {
                    p++;
                    boost::hash_combine(seed, boost::make_iterator_range(b, p));
                    b = p;
                    cr = false;
                    lf = true;
                }
                else if (p == b) // '\n'
                {
                    p++;
                    boost::hash_combine(seed, boost::as_literal("\r\n"));
                    b = p;
                    cr = false;
                    lf = true;
                }
                else           // '*\n'
                {
                    boost::hash_combine(seed, boost::make_iterator_range(b, p));
                    boost::hash_combine(seed, boost::as_literal("\r\n"));
                    p++;
                    b = p;
                    cr = false;
                    lf = true;
                }
            }
            if (b != p)
            {
                assert(cr);
                boost::hash_combine(seed, boost::make_iterator_range(b, p));
                b = p;
            }

            pp += (p - p0);
            bb = pp;
        }
    }
    return seed;
}

static std::size_t gen_id(std::size_t seed)
{
    boost::hash_combine(seed, time(0));
    boost::hash_combine(seed, ::getpid());
    boost::hash_combine(seed, boost::lexical_cast<std::string>(
        boost::this_thread::get_id()));
    return seed;
}

// --
class greylisting_client::request
        : public basic_rc_request<request_handler_t>
{
  public:
    typedef basic_rc_request<request_handler_t> base;

    handler_t handler;

    request(boost::asio::io_service& ios,
            boost::asio::ip::udp::endpoint host,
            request_handler_t h,
            handler_t hh)
            : base(ios, host, h),
              handler(hh)
    {
    }
};

greylisting_client::greylisting_client(boost::asio::io_service& ios,
        const greylisting_options& opt,
        const hostlist& list)
        : opt_(opt),
          l_(list),
          cl_(ios)
{
}

void greylisting_client::probe(const key& k, const std::string& comment, handler_t handler)
{
    request_handler_t h(
        boost::bind(&greylisting_client::handle_probe, shared_from_this(), _1, _2));
    std::size_t keyhash = hash_value(k, opt_);
    boost::asio::ip::udp::endpoint host( *(l_.begin() + (keyhash % l_.size())) );

    boost::shared_ptr<request> req(
        new request(
            cl_.io_service(),
            host,
            h,
            handler));

    request_pb& q = req->q_pb;

    i_.suid = k.envelope_to;
    i_.keyhash = keyhash;
    i_.host = host;
    i_.valid = false;

    // Encode request_pb
    q.set_id(gen_id(keyhash));
    q.set_command(request_pb::GET);
    q.set_key_namespace(opt_.ns);
    q.set_key(boost::lexical_cast<std::string>(keyhash));
    q.set_ttl(opt_.record_lifetime);
    q.set_comment(comment);
    q.add_param(1);

    cl_.start(req, boost::posix_time::seconds(opt_.udp_timeout));
}

void greylisting_client::mark(const std::string& comment, handler_t handler)
{
    request_handler_t h(
        boost::bind(&greylisting_client::handle_mark, shared_from_this(), _1, _2));
    std::size_t keyhash = i_.keyhash;
    const boost::asio::ip::udp::endpoint& host = i_.host;

    if (!i_.valid)
        return handler( make_error_code(logical_error), host);

    boost::shared_ptr<request> req(
        new request(
            cl_.io_service(),
            host,
            h,
            handler));

    request_pb& q = req->q_pb;

    // Encode request_pb
    q.set_id(gen_id(keyhash));
    q.set_command(request_pb::ADD);
    q.set_key_namespace(opt_.ns);
    q.set_key(boost::lexical_cast<std::string>(keyhash));
    q.set_ttl(opt_.record_lifetime);
    q.set_comment(comment);
    q.add_param(1);
    if (i_.passed)
        q.add_param(1);

    cl_.start(req, boost::posix_time::seconds(opt_.udp_timeout));
}


void greylisting_client::stop()
{
    cl_.stop();
}

void greylisting_client::handle_probe(const boost::system::error_code& ec,
        boost::shared_ptr<request> req)
{
    const reply_pb& a = req->reply();
    boost::system::error_code rv_ec = ec;
    if (ec)
        ;
    else if (a.age() < opt_.window_begin)
        rv_ec = make_error_code(too_early);
    else if (a.age() > opt_.window_end)
        rv_ec = make_error_code(too_late);
    else
        rv_ec = boost::system::error_code();

    i_.age = a.age();
    i_.n = (a.result_size() > 0) ? a.result().Get(0) : 0;
    i_.m = (a.result_size() > 1) ? a.result().Get(1) : 0;
    i_.passed = false;
    i_.valid = true;
    i_.passed = !rv_ec;

    return req->handler( rv_ec, req->host() );
}

void greylisting_client::handle_mark(const boost::system::error_code& ec,
        boost::shared_ptr<request> req)
{
    const reply_pb& a = req->reply();
    boost::system::error_code rv_ec = ec;
    if (ec)
        ;
    else if (a.age() < opt_.window_begin)
        rv_ec = make_error_code(too_early);
    else if (a.age() > opt_.window_end)
        rv_ec = make_error_code(too_late);
    else
        rv_ec = boost::system::error_code();

    return req->handler( rv_ec, req->host() );
}
