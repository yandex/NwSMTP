#include "adkim.h"

#define new a_better_variable_name
#define _Bool bool
#include <opendkim/dkim.h>
#undef new
#undef _Bool

#include <net/dns_resolver.hpp>
#include <boost/thread.hpp>
#include <boost/array.hpp>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

using namespace y::net;

typedef ybuffers_iterator<ystreambuf::const_buffers_type> yconst_buffers_iterator;

namespace {
inline DKIM_STAT dkim_chunk_helper(DKIM *dkim, const char *chunkp, size_t len)
{
    return dkim_chunk(dkim, const_cast<u_char*>(reinterpret_cast<const u_char*>(chunkp)), len);
}

extern "C" typedef DKIM_CBSTAT (key_lookup_func_t)(DKIM*, DKIM_SIGINFO*, unsigned char*, size_t);
extern "C" key_lookup_func_t y_dkim_key_lookup_collect;
extern "C" key_lookup_func_t y_dkim_key_lookup_seed;

struct dkim_lib_loader : private boost::noncopyable
{
    DKIM_LIB* lib;
    dkim_lib_loader()
            : lib(dkim_init(NULL, NULL))
    {}

    ~dkim_lib_loader()
    {
        if (lib)
            dkim_close(lib);
    }
};

template <class KeyLookup>
class dkim_lib_singleton
{
    static boost::scoped_ptr<dkim_lib_loader> ptr_;
    static boost::once_flag flag_;

  public:
    static DKIM_LIB* instance()
    {
        boost::call_once(init, flag_);
        return ptr_->lib;
    }

    static void init()
    {
        ptr_.reset(new dkim_lib_loader);
        dkim_set_key_lookup(ptr_->lib, KeyLookup()());
    }
};

template <class T> boost::scoped_ptr<dkim_lib_loader> dkim_lib_singleton<T>::ptr_;
template <class T> boost::once_flag dkim_lib_singleton<T>::flag_ = BOOST_ONCE_INIT;

struct key_collect_adaptor
{
    key_lookup_func_t* operator()()
    {
        return y_dkim_key_lookup_collect;
    }
};

struct key_seed_adaptor
{
    key_lookup_func_t* operator()()
    {
        return y_dkim_key_lookup_seed;
    }
};

dkim_lib_singleton<key_collect_adaptor> lib0;
dkim_lib_singleton<key_seed_adaptor> lib1;
} // namespace


struct dkim_check::dkim_check_impl :  public boost::enable_shared_from_this<dkim_check::dkim_check_impl>,
                                      private boost::noncopyable
{
    typedef boost::array<char, DKIM_MAXHOSTNAMELEN + 1> req_t;
    typedef std::string res_t;
    typedef std::pair<req_t, res_t> query_t;
    typedef std::list<query_t> ql_t;

    dkim_parameters p_;
    dns::resolver r_;
    boost::mutex mux_;
    bool done_;
    DKIM* dkim_;
    ql_t ql_; // dns queries

    dkim_check_impl(boost::asio::io_service& ios, const dkim_parameters& pp)
            : p_(pp),
              r_(ios),
              done_(false),
              dkim_(0)
    {
    }

    ~dkim_check_impl()
    {
        if (dkim_)
            dkim_free(dkim_);
    }

    void start(dkim_check::handler_t handler);
    void cont(dkim_check::handler_t handler);
    DKIM_STAT helper(yconst_buffers_iterator b,
            const yconst_buffers_iterator& e);
    void complete();
};

typedef boost::shared_ptr<dkim_check::dkim_check_impl> dkim_check_impl_ptr;

namespace {
extern "C" DKIM_CBSTAT y_dkim_key_lookup_seed (DKIM *dkim, DKIM_SIGINFO *sig,
        unsigned char *buf, size_t buflen)
{
    void* ctx = const_cast<void*>(dkim_get_user_context(dkim));
    if (!ctx)
        return DKIM_STAT_NORESOURCE;

    typedef dkim_check::dkim_check_impl impl_t;
    dkim_check_impl_ptr impl = reinterpret_cast<impl_t*>(ctx)->shared_from_this();

    impl_t::req_t req;
    int n = snprintf(req.data(), req.size() - 1, "%s.%s.%s", dkim_sig_getselector(sig),
            DKIM_DNSKEYNAME, dkim_sig_getdomain(sig));
    if (n == -1 || static_cast<size_t>(n) > req.size())
    {
        return DKIM_STAT_NORESOURCE;
    }

    if (impl->ql_.empty())
        return DKIM_STAT_NOKEY;

    impl_t::ql_t::iterator qlit = impl->ql_.begin();
    if (!strncmp(qlit->first.data(), req.data(), req.size()))
    {
        impl_t::res_t& res = qlit->second;

        memcpy(buf, res.data(), std::min(res.size(), buflen));
        return DKIM_STAT_OK;
    }
    else
    {
        impl->ql_.erase(qlit);
        return DKIM_STAT_NOKEY;
    }

    return DKIM_STAT_KEYFAIL;
}

void y_dkim_key_lookup_collect_helper(const boost::system::error_code& ec, dns::resolver::iterator it,
        dkim_check_impl_ptr impl,
        dkim_check::dkim_check_impl::ql_t::iterator qlit,
        dkim_check::handler_t handler)
{
    if (ec == boost::asio::error::operation_aborted || impl->done_)
        return;

    dkim_check::dkim_check_impl::ql_t::iterator qlit_saved = qlit++;
    if (ec)
    {
        impl->ql_.erase(qlit_saved);
    }
    else if (boost::shared_ptr<dns::txt_resource> tr = boost::dynamic_pointer_cast<dns::txt_resource>(*it))
    {
        dkim_check::dkim_check_impl::res_t& res = qlit_saved->second;
        res = tr->text();
    }

    if (qlit != impl->ql_.end())
    {
        boost::mutex::scoped_lock lock(impl->mux_);
        dkim_check::dkim_check_impl::req_t& req = qlit->first;
        impl->r_.async_resolve(req.data(), dns::type_txt,
                boost::bind(y_dkim_key_lookup_collect_helper,
                        _1, _2, impl, qlit, handler)
                               );
    }
    else // last request was resolved
    {
        impl->cont(handler);
    }
}

extern "C" DKIM_CBSTAT y_dkim_key_lookup_collect (DKIM *dkim, DKIM_SIGINFO *sig,
        unsigned char *buf, size_t buflen)
{
    void* ctx = const_cast<void*>(dkim_get_user_context(dkim));
    if (!ctx)
        return DKIM_STAT_NORESOURCE;

    typedef dkim_check::dkim_check_impl impl_t;
    dkim_check_impl_ptr impl = reinterpret_cast<impl_t*>(ctx)->shared_from_this();
    impl->ql_.resize( impl->ql_.size() + 1 );
    impl_t::query_t& q = impl->ql_.back();
    impl_t::req_t& req = q.first;
    int n = snprintf(req.data(), req.size() - 1, "%s.%s.%s", dkim_sig_getselector(sig),
            DKIM_DNSKEYNAME, dkim_sig_getdomain(sig));
    if (n == -1 || static_cast<size_t>(n) > req.size())
    {
        return DKIM_STAT_NORESOURCE;
    }

    return DKIM_STAT_NOKEY;
}
} // namespace

const char* dkim_check::status(DKIM_STATUS s)
{
    switch (s)
    {
        case DKIM_PASS:
            return "pass";
        case DKIM_FAIL:
            return "fail";
        case DKIM_NEUTRAL:
            return "neutral";
        case DKIM_NONE:
        default:
            return "none";
    }
}

DKIM_STAT dkim_check::dkim_check_impl::helper(yconst_buffers_iterator bb,
        const yconst_buffers_iterator& ee)
{
    yconst_buffers_iterator pp = bb;
    bool cr = false;
    bool lf = false;
    DKIM_STAT st = DKIM_STAT_OK;
    while (pp != ee && st == DKIM_STAT_OK)
    {
        const char* b0 = &*bb;
        const char* p0 = &*pp;
        const char* b = b0;
        const char* p = p0;
        const char* e = ptr_end(pp, ee);

        while (p != e && st == DKIM_STAT_OK)
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
                st = dkim_chunk_helper(dkim_, b, p-b);
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
                st = dkim_chunk_helper(dkim_, b, p-b);
                b = p;
                cr = false;
                lf = true;
            }
            else if (p == b) // '\n'
            {
                p++;
                st = dkim_chunk_helper(dkim_, "\r\n", 2);
                b = p;
                cr = false;
                lf = true;
            }
            else           // '*\n'
            {
                st = dkim_chunk_helper(dkim_, b, p-b);
                if (st == DKIM_STAT_OK)
                    st = dkim_chunk_helper(dkim_, "\r\n", 2);
                p++;
                b = p;
                cr = false;
                lf = true;
            }
        }
        if (b != p && st == DKIM_STAT_OK)
        {
            assert(cr);
            st = dkim_chunk_helper(dkim_, b, p-b);
            b = p;
        }

        pp += (p - p0);
        bb = pp;
    }

    dkim_chunk(dkim_, NULL, 0);
    return st;
}

dkim_check::dkim_check()
{}

void dkim_check::stop()
{
    if (impl_)
    {
        boost::mutex::scoped_lock lock(impl_->mux_);
        impl_->r_.cancel();
        impl_->done_ = true;
        lock.unlock();

        impl_.reset();
    }
}

bool dkim_check::is_inprogress() const
{
    return impl_ && !impl_->done_;
}

void dkim_check::dkim_check_impl::cont(dkim_check::handler_t handler)
{
    if (dkim_)
    {
        dkim_free(dkim_);
        dkim_ = 0;
    }

    DKIM_STAT st;
    const unsigned char empty[] = {0};
    if ( ! (dkim_ = dkim_verify(lib1.instance(), empty, NULL, &st)) ||
            (st != DKIM_STAT_OK) )
    {
        done_ = true;
        return handler(DKIM_NEUTRAL, std::string());
    }

    void* ctx = this;
    dkim_set_user_context(dkim_, reinterpret_cast<const char*>(ctx));

    st = helper(p_.b, p_.e);

    if (done_) // See if the request was canceled
        return handler(DKIM_NEUTRAL, std::string());

    done_ = true;

    if (st == DKIM_STAT_NOSIG)
        return handler(DKIM_NONE, std::string());
    else if (st != DKIM_STAT_OK)
        return handler(DKIM_NEUTRAL, std::string());

    st = dkim_eom(dkim_, NULL);

    boost::array<u_char, 256> identity;
    memset(identity.data(), 0, identity.size());

    if (DKIM_SIGINFO* sig = dkim_getsignature(dkim_))
        dkim_sig_getidentity(dkim_, sig, identity.data(), identity.size()-1);

    if (st == DKIM_STAT_OK)
        return handler(DKIM_PASS, std::string(identity.begin(), identity.end()));
    else if (st == DKIM_STAT_BADSIG)
        return handler(DKIM_FAIL, std::string(identity.begin(), identity.end()));
    return handler(DKIM_NEUTRAL, std::string(identity.begin(), identity.end()));
}

void dkim_check::dkim_check_impl::start(dkim_check::handler_t handler)
{
    assert (!dkim_);
    DKIM_STAT st;
    const unsigned char empty[] = {0};
    if ( !(dkim_ = dkim_verify(lib0.instance(), empty, NULL, &st)) ||
            (st != DKIM_STAT_OK) )
    {
        done_ = true;
        return handler(DKIM_NEUTRAL, std::string());
    }

#if 0
    unsigned int dkflags = 0;
    dkim_options(lib_, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS, &dkflags, sizeof dkflags);
    dkflags |= DKIM_LIBFLAGS_VERIFYONE;
    dkim_options(lib_, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &dkflags, sizeof dkflags);
#endif

    void* ctx = this;
    dkim_set_user_context(dkim_, reinterpret_cast<const char*>(ctx));

    helper(p_.b, p_.bs);

    if (ql_.empty())
    {
        done_ = true;
        return handler(DKIM_NEUTRAL, std::string());
    }

    boost::mutex::scoped_lock lock(mux_);
    ql_t::iterator qlit = ql_.begin();
    req_t& req = qlit->first;
    r_.async_resolve(req.data(), dns::type_txt,
            boost::bind(y_dkim_key_lookup_collect_helper,
                    _1, _2, shared_from_this(), qlit, handler)
                     );
}

void dkim_check::start(boost::asio::io_service& ios, const dkim_parameters& p, dkim_check::handler_t handler)
{
    impl_.reset(new dkim_check_impl(ios, p));
    impl_->start(handler);
}

