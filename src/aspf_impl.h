#ifndef ASPF_IMPL_H
#define ASPF_IMPL_H

#include <net/dns_resolver.hpp>
#include <boost/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>
#include <boost/unordered_map.hpp>
#include <boost/bind/protect.hpp>
#include <boost/optional.hpp>
#include "uti.h"

namespace impl
{

extern "C"
{
#include <spf2/spf.h>
}

extern "C"
{
#include <spf2/spf.h>
#include "spf_internal.h"
}

using namespace std;
using namespace y::net;

typedef pair<string, ns_type> lookup_key;
struct dns_data
{
    typedef boost::unordered_map<lookup_key, boost::shared_ptr<SPF_dns_rr_t> > hash_t;
    hash_t hash;
    boost::mutex mutex;
};

inline SPF_dns_rr_t* clone_SPF_dns_rr(boost::shared_ptr<SPF_dns_rr_t> rr)
{
    SPF_dns_rr_t* new_rr = 0;
    SPF_dns_rr_dup(&new_rr, rr.get());
    return new_rr;
}

inline dns_data* get_dns_data(SPF_dns_server_t* d)
{   return static_cast<dns_data*>(d->hook);    }

inline void insert_dns_data(SPF_dns_server_t* d, boost::shared_ptr<SPF_dns_rr_t> rr)
{
    dns_data* dd =  get_dns_data(d);
    boost::mutex::scoped_lock lock(dd->mutex);
    dd->hash.insert(dns_data::hash_t::value_type(lookup_key(rr->domain, rr->rr_type), rr));
}

inline bool has_dns_data(SPF_dns_server_t* d, const string& domain, ns_type t)
{
    dns_data* dd =  get_dns_data(d);
    boost::mutex::scoped_lock lock(dd->mutex);
    return dd->hash.find(lookup_key(domain, t)) != dd->hash.end();
}

extern "C" SPF_dns_rr_t* ydns_resolv_lookup(SPF_dns_server_t* d,
        const char *domain, ns_type ns_type, int)
{
    dns_data* dd = get_dns_data(d);
    boost::mutex::scoped_lock lock(dd->mutex);
    if (ns_type == ns_t_spf)
        ns_type = ns_t_txt;
    dns_data::hash_t::iterator it = dd->hash.find( lookup_key(domain, ns_type) );
    if (it != dd->hash.end())
        return clone_SPF_dns_rr(it->second);

    return SPF_dns_rr_new_init(d, domain, ns_type, 0, 0);
}

extern "C" void free_spf_dns_resolver(SPF_dns_server_t* d)
{
    delete static_cast<dns_data*>(d->hook);
    delete d;
}

SPF_dns_server_t* create_spf_dns_resolver(SPF_dns_server_t* layer_below, int debug)
{
    SPF_dns_server_t* spf_dns = new SPF_dns_server_t;
    if (!spf_dns)
        return spf_dns;

    spf_dns->destroy     = NULL;
    spf_dns->lookup      = ydns_resolv_lookup;
    spf_dns->get_spf     = NULL;
    spf_dns->get_exp     = NULL;
    spf_dns->add_cache   = NULL;
    spf_dns->layer_below = layer_below;
    spf_dns->name        = "yresolv";
    spf_dns->debug       = debug;
    spf_dns->hook        = new dns_data;

    return spf_dns;
}

boost::shared_ptr<SPF_dns_rr_t> create_spf_dns_txt_rr(SPF_dns_server_t* d, const string& domain, const string& text)
{
    SPF_dns_rr_t* rr = SPF_dns_rr_new_init(d, domain.c_str(), ns_t_txt, 0, 0);
    if (!rr)
        return boost::shared_ptr<SPF_dns_rr_t>();
    SPF_dns_rr_buf_realloc(rr, 0, text.size()+1);
    strcpy(rr->rr[0]->txt, text.c_str());
    rr->num_rr++;
    return boost::shared_ptr<SPF_dns_rr_t>(rr, SPF_dns_rr_free);
}

boost::shared_ptr<SPF_dns_rr_t> create_spf_dns_ptr_rr(SPF_dns_server_t* d, const string& domain, dns::resolver::iterator it)
{
    SPF_dns_rr_t* rr = SPF_dns_rr_new_init(d, domain.c_str(), ns_t_ptr, 0, 0);
    if (!rr)
        return boost::shared_ptr<SPF_dns_rr_t>();
    int i=0;
    for ( ; it != dns::resolver::iterator() ; ++it, ++i)
    {
        boost::shared_ptr<dns::ptr_resource> pr = boost::dynamic_pointer_cast<dns::ptr_resource>(*it);
        SPF_dns_rr_buf_realloc(rr, i, pr->pointer().size()+1);
        strcpy(rr->rr[i]->txt, pr->pointer().c_str());
        rr->num_rr++;
    }
    return boost::shared_ptr<SPF_dns_rr_t>(rr, SPF_dns_rr_free);
}

boost::shared_ptr<SPF_dns_rr_t> create_spf_dns_mx_rr(SPF_dns_server_t* d, const string& domain, dns::resolver::iterator it)
{
    SPF_dns_rr_t* rr = SPF_dns_rr_new_init(d, domain.c_str(), ns_t_mx, 0, 0);
    if (!rr)
        return boost::shared_ptr<SPF_dns_rr_t>();
    int i=0;
    for ( ; it != dns::resolver::iterator() ; ++it, ++i)
    {
        boost::shared_ptr<dns::mx_resource> mr = boost::dynamic_pointer_cast<dns::mx_resource>(*it);
        SPF_dns_rr_buf_realloc(rr, i, mr->exchange().size()+1);
        strcpy(rr->rr[i]->mx, mr->exchange().c_str());
        rr->num_rr++;
    }
    return boost::shared_ptr<SPF_dns_rr_t>(rr, SPF_dns_rr_free);
}

boost::shared_ptr<SPF_dns_rr_t> create_spf_dns_a_rr(SPF_dns_server_t* d, const string& domain, dns::resolver::iterator it)
{
    SPF_dns_rr_t* rr = SPF_dns_rr_new_init(d, domain.c_str(), ns_t_a, 0, 0);
    if (!rr)
        return boost::shared_ptr<SPF_dns_rr_t>();
    int i=0;
    for ( ; it != dns::resolver::iterator() ; ++it, ++i)
    {
        boost::shared_ptr<dns::a_resource> ar = boost::dynamic_pointer_cast<dns::a_resource>(*it);
        SPF_dns_rr_buf_realloc(rr, i, ar->address().to_string().size()+1);
        inet_pton( AF_INET, ar->address().to_string().c_str(), &rr->rr[i]->a);
        rr->num_rr++;
    }
    return boost::shared_ptr<SPF_dns_rr_t>(rr, SPF_dns_rr_free);
}

boost::shared_ptr<SPF_dns_rr_t> create_spf_dns_a_rr();
boost::shared_ptr<SPF_dns_rr_t> create_spf_dns_mx_rr();

template <class T>
class yscoped_ptr_helper_base
{
  public:
    virtual ~yscoped_ptr_helper_base() {}
    virtual void dispose(T* t) = 0;
};

template <class T, class D>
class yscoped_ptr_helper_td : public yscoped_ptr_helper_base<T>
{
    D del;
  public:
    yscoped_ptr_helper_td(D d)
            : del(d)
    {}

    void dispose(T* t)
    {
        if (t)
            del(t);
    }
};

template <class T>
class yscoped_ptr_helper_t : public yscoped_ptr_helper_base<T>
{
  public:
    void dispose(T* t)
    {
        delete t;
    }
};

template<class T>
class yscoped_ptr : private boost::noncopyable
{
    T* px;
    yscoped_ptr_helper_base<T>* ph;
    typedef yscoped_ptr<T> this_type;

  public:
    template <class D>
    yscoped_ptr(T* t, D d)
            : px(t), ph(new yscoped_ptr_helper_td<T, D>(d))
    {
    }

    yscoped_ptr(T* t = 0)
            : px(t), ph(new yscoped_ptr_helper_t<T>)
    {
    }

    ~yscoped_ptr()
    {
        if (px)
        {
            ph->dispose(px);
            px = 0;
        }
        delete ph;
        ph = 0;
    }

    operator bool()
    {
        return px != 0;
    }

    void reset(T* p = 0)
    {
        if (px)
            ph->dispose(px);
        px = p;
    }

    T* release()
    {
        T* tpx = px;
        px = 0;
        return tpx;
    }

    T& operator*() const
    {
        return *px;
    }

    T* operator->() const
    {
        return px;
    }

    T* get() const
    {
        return px;
    }
};

struct collect_shared_state : private boost::noncopyable
{
    collect_shared_state(boost::asio::io_service& ios, SPF_server_t* srv_ = 0,
            SPF_dns_server_t* dns_ = 0, SPF_request_t* req_ = 0)
            : srv(srv_), dns(dns_), req(req_),
              r(ios),
              inprogress(0),
              done(false)
    {
    }

    ~collect_shared_state()
    {
        if (req)
            SPF_request_free(req);
        if (dns)
            free_spf_dns_resolver(dns);
        if (srv)
            SPF_server_free(srv);
    }

    SPF_server_t* srv;
    SPF_dns_server_t* dns;
    SPF_request_t* req;
    dns::resolver r;
    int inprogress;
    bool done;
    boost::mutex mux;
};

struct collect_state
{
    collect_state(boost::shared_ptr<collect_shared_state> st, string dom, bool e=false)
            : shared_state(st), cur_dom(dom), err(e)
    {}

    boost::shared_ptr<collect_shared_state> shared_state;
    string cur_dom;
    bool err;
};

template <class Handle>
inline void handle_partial_collect_spf_dns_data(collect_state st, Handle handle)
{
    if (! --st.shared_state->inprogress)
        handle(st);
}

template <class Handle>
void handle_resolve_txt_exp(const boost::system::error_code& ec, dns::resolver::iterator it,
        collect_state st, Handle handle)
{
    if (ec == boost::asio::error::operation_aborted || st.shared_state->done)
        return;

    if (!ec)
    {
        boost::shared_ptr<dns::txt_resource> tr = boost::dynamic_pointer_cast<dns::txt_resource>(*it);
        boost::shared_ptr<SPF_dns_rr_t> spf_rr = create_spf_dns_txt_rr(st.shared_state->dns, st.cur_dom, tr->text());
        insert_dns_data(st.shared_state->dns, spf_rr);
        handle_partial_collect_spf_dns_data(st, handle);
        return;
    }
    handle_partial_collect_spf_dns_data(collect_state(st.shared_state, st.cur_dom, true), handle);
}

template <class Handle>
void handle_resolve_txt(const boost::system::error_code& ec, dns::resolver::iterator it,
        collect_state st, Handle handle)
{
    if (ec == boost::asio::error::operation_aborted || st.shared_state->done)
        return;

    while (!ec || st.shared_state->done)
    {
        SPF_errcode_t err = SPF_E_SUCCESS;
        SPF_record_t* r = 0;
        yscoped_ptr<SPF_record_t> r_guard(0, SPF_record_free);
        yscoped_ptr<SPF_response_t> spf_res(0, SPF_response_free);

        for (; it != dns::resolver::iterator(); ++it)
        {
            boost::shared_ptr<dns::txt_resource> tr = boost::dynamic_pointer_cast<dns::txt_resource>(*it);
            r_guard.reset(0);
            r = 0;
            spf_res.reset(SPF_response_new(st.shared_state->req));
            err = SPF_record_compile(st.shared_state->srv, spf_res.get(), &r, tr->text().c_str());
            r_guard.reset(r);
            if (err == SPF_E_SUCCESS)
            {
                boost::shared_ptr<SPF_dns_rr_t> spf_rr = create_spf_dns_txt_rr(st.shared_state->dns, st.cur_dom, tr->text());
                insert_dns_data(st.shared_state->dns, spf_rr);

                char* buf = NULL;
                size_t buf_len = 0;
                int err = SPF_record_find_mod_value(st.shared_state->srv, st.shared_state->req,
                        spf_res.get(), r,
                        SPF_EXP_MOD_NAME, &buf, &buf_len);
                if (err)
                    err = SPF_record_find_mod_value(st.shared_state->srv, st.shared_state->req,
                            spf_res.get(), r,
                            "exp", &buf, &buf_len);
                yscoped_ptr<char> buf_guard(buf, free);
                if (err == SPF_E_SUCCESS)
                {
                    collect_state nst(st.shared_state, string(buf));
                    collect_spf_dns_data_exp(nst, handle);
                }
                break; // we need exactly 1 compilable spf record
            }
        }

        if (err != SPF_E_SUCCESS)
            break;

        SPF_mech_t* mech = r->mech_first;
        SPF_data_t* data = 0;
        SPF_data_t* data_end = 0;
        char* buf = NULL;
        size_t buf_len = 0;
        yscoped_ptr<char> buf_guard(0, free);
        const char* lookup = 0;

        for (int m = 0; m < r->num_mech; m++, mech=SPF_mech_next(mech)) {
            if (spf_res->num_dns_mech > st.shared_state->srv->max_dns_mech)
                break;
            data = SPF_mech_data(mech);
            data_end = SPF_mech_end_data(mech);
            switch (mech->mech_type) {
                case MECH_A:
                    if (data < data_end && data->dc.parm_type == PARM_CIDR)
                        data = SPF_data_next(data);
                    if (data == data_end)
                        lookup = st.cur_dom.c_str();
                    else
                    {
                        buf_guard.release();
                        err = SPF_record_expand_data(st.shared_state->srv,
                                st.shared_state->req, spf_res.get(),
                                data, ((char*)data_end - (char*)data),
                                &buf, &buf_len);
                        buf_guard.reset(buf);
                        lookup = buf;
                    }
                    if (err)
                        break;

                    collect_spf_dns_data_a(collect_state(st.shared_state, lookup), handle);
                    break;

                case MECH_MX:
                    if (data < data_end && data->dc.parm_type == PARM_CIDR)
                        data = SPF_data_next(data);
                    if (data == data_end)
                        lookup = st.cur_dom.c_str();
                    else
                    {
                        buf_guard.release();
                        err = SPF_record_expand_data(st.shared_state->srv,
                                st.shared_state->req, spf_res.get(),
                                data, ((char*)data_end - (char*)data),
                                &buf, &buf_len);
                        buf_guard.reset(buf);
                        lookup = buf;
                    }
                    if (err)
                        break;

                    collect_spf_dns_data_mx(collect_state(st.shared_state, lookup), handle);
                    break;

                case MECH_PTR:
                    {
                        typedef boost::asio::ip::address_v4::bytes_type bytes_type;
                        bytes_type ipv4;
                        memcpy(&ipv4.elems, reinterpret_cast<typename bytes_type::value_type*>(&st.shared_state->req->ipv4.s_addr), 4);
                        collect_spf_dns_data_ptr(collect_state(st.shared_state,
                                        rev_order_av4_str(boost::asio::ip::address_v4(ipv4),
                                                "in-addr.arpa")),
                                handle);
                    }
                    break;

                case MECH_INCLUDE:
                case MECH_REDIRECT:
                    buf_guard.release();
                    err = SPF_record_expand_data(st.shared_state->srv,
                            st.shared_state->req, spf_res.get(),
                            SPF_mech_data(mech), SPF_mech_data_len(mech),
                            &buf, &buf_len );
                    buf_guard.reset(buf);
                    if (err)
                        break;

                    if (has_dns_data(st.shared_state->dns, buf, ns_t_txt)) // see if we go in circles
                    {
                        err = SPF_E_RECURSIVE;
                        break;
                    }

                    collect_spf_dns_data_redirect(collect_state(st.shared_state, buf), handle);
                    break;

                case MECH_EXISTS:
                    buf_guard.release();
                    err = SPF_record_expand_data(st.shared_state->srv,
                            st.shared_state->req, spf_res.get(),
                            SPF_mech_data(mech),SPF_mech_data_len(mech),
                            &buf, &buf_len);
                    buf_guard.reset(buf);
                    if (err)
                        break;

                    collect_spf_dns_data_a(collect_state(st.shared_state, buf), handle);
                    break;

                default:
                    break;
            }
            if (err)
                break;
        }

        if (err)
            break;

        handle_partial_collect_spf_dns_data(st, handle);
        return;
    }

    handle_partial_collect_spf_dns_data(collect_state(st.shared_state, st.cur_dom, true), handle);
}

template <class Handle>
void handle_resolve_a(const boost::system::error_code& ec, dns::resolver::iterator it,
        collect_state st, Handle handle)
{
    if (ec == boost::asio::error::operation_aborted || st.shared_state->done)
        return;

    boost::shared_ptr<SPF_dns_rr_t> spf_rr = create_spf_dns_a_rr(st.shared_state->dns, st.cur_dom, it);
    insert_dns_data(st.shared_state->dns, spf_rr);

    if (!ec)
    {
        boost::shared_ptr<dns::a_resource> ar = boost::dynamic_pointer_cast<dns::a_resource>(*it);
        handle_partial_collect_spf_dns_data(st, handle);
        return;
    }

    handle_partial_collect_spf_dns_data(collect_state(st.shared_state, st.cur_dom, true), handle);
}


template <class Handle>
void collect_spf_dns_data_a(collect_state st, Handle handle)
{
    st.shared_state->inprogress++;
    boost::mutex::scoped_lock lock(st.shared_state->mux);
    st.shared_state->r.async_resolve(st.cur_dom, dns::type_a,
            boost::bind(handle_resolve_a<Handle>,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::iterator,
                    st,
                    handle)
                                     );
}

template <class Handle>
void handle_resolve_mx(const boost::system::error_code& ec, dns::resolver::iterator it,
        collect_state st, Handle handle)
{
    if (ec == boost::asio::error::operation_aborted || st.shared_state->done)
        return;

    boost::shared_ptr<SPF_dns_rr_t> spf_rr = create_spf_dns_mx_rr(st.shared_state->dns, st.cur_dom, it);
    insert_dns_data(st.shared_state->dns, spf_rr);

    if (!ec)
    {
        for( ; it != dns::resolver::iterator(); ++it)
        {
            boost::shared_ptr<dns::mx_resource> mr = boost::dynamic_pointer_cast<dns::mx_resource>(*it);
            collect_spf_dns_data_a(collect_state(st.shared_state, mr->exchange()), handle);
        }
        handle_partial_collect_spf_dns_data(st, handle);
        return;
    }

    handle_partial_collect_spf_dns_data(collect_state(st.shared_state, st.cur_dom, true), handle);
}


template <class Handle>
void collect_spf_dns_data_mx(collect_state st, Handle handle)
{
    st.shared_state->inprogress++;
    boost::mutex::scoped_lock lock(st.shared_state->mux);
    st.shared_state->r.async_resolve(st.cur_dom, dns::type_mx,
            boost::bind(handle_resolve_mx<Handle>,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::iterator,
                    st,
                    handle)
                                     );
}

template <class Handle>
void handle_resolve_ptr(const boost::system::error_code& ec, dns::resolver::iterator it,
        collect_state st, Handle handle)
{
    if (ec == boost::asio::error::operation_aborted || st.shared_state->done)
        return;

    boost::shared_ptr<SPF_dns_rr_t> spf_rr = create_spf_dns_ptr_rr(st.shared_state->dns, st.cur_dom, it);
    insert_dns_data(st.shared_state->dns, spf_rr);

    if (!ec)
    {
        for( ; it != dns::resolver::iterator(); ++it)
        {
            boost::shared_ptr<dns::ptr_resource> pr = boost::dynamic_pointer_cast<dns::ptr_resource>(*it);
            collect_spf_dns_data_a(collect_state(st.shared_state, pr->pointer()), handle);
        }
        handle_partial_collect_spf_dns_data(st, handle);
        return;
    }

    handle_partial_collect_spf_dns_data(collect_state(st.shared_state, st.cur_dom, true), handle);
}

template <class Handle>
void collect_spf_dns_data_ptr(collect_state st, Handle handle)
{
    st.shared_state->inprogress++;
    boost::mutex::scoped_lock lock(st.shared_state->mux);
    st.shared_state->r.async_resolve(st.cur_dom, dns::type_ptr,
            boost::bind(handle_resolve_ptr<Handle>,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::iterator,
                    st,
                    handle)
                                     );
}

template <class Handle>
void collect_spf_dns_data_exp(collect_state st, Handle handle)
{
    st.shared_state->inprogress++;
    if (!st.cur_dom.empty())
    {
        boost::mutex::scoped_lock lock(st.shared_state->mux);
        st.shared_state->r.async_resolve(
            st.cur_dom,
            dns::type_txt,
            boost::bind(handle_resolve_txt_exp<Handle>,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::iterator,
                    st,
                    handle)
            );
    }
    else
    {
        handle_partial_collect_spf_dns_data(collect_state(st.shared_state, st.cur_dom, true), handle);
    }
}

template <class Handle>
void collect_spf_dns_data_redirect(collect_state st, Handle handle)
{
    st.shared_state->inprogress++;
    if (!st.cur_dom.empty())
    {
        boost::mutex::scoped_lock lock(st.shared_state->mux);
        st.shared_state->r.async_resolve(
            st.cur_dom,
            dns::type_txt,
            boost::bind(handle_resolve_txt<Handle>,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::iterator,
                    st,
                    handle)
            );
    }
    else
    {
        handle_partial_collect_spf_dns_data(collect_state(st.shared_state, st.cur_dom, true), handle);
    }
}

template <class Handle>
void continue_spf_check(collect_state st, Handle handle)
{
    SPF_response_t* res = 0;
    SPF_request_query_mailfrom(st.shared_state->req, &res);

    yscoped_ptr<SPF_response_t> spf_res(res, SPF_response_free);

    boost::optional<string> result;
    boost::optional<string> expl;

    if (SPF_RESULT_NONE != SPF_response_result(res))
    {
        const char* str = SPF_response_get_header_comment(res);
        if (str)
            expl = boost::optional<string>(str);
        SPF_result_t spf = SPF_response_result(res);
        str = SPF_strresult(spf);
        if (str)
            result = boost::optional<string>(str);
    }

    st.shared_state->done = true;
    handle( result, expl );
}

collect_state create_init_collect_state(boost::asio::io_service& ios, const spf_parameters& p)
{
    boost::shared_ptr<collect_shared_state> sst( new collect_shared_state(ios) );
    try
    {
        if (!sst)
            return collect_state(sst, p.domain, true);

        sst->dns = create_spf_dns_resolver(NULL, 0);
        sst->srv = SPF_server_new_dns(sst->dns, 0);
        sst->req = SPF_request_new(sst->srv);
        return collect_state(sst, p.domain, false);
    }
    catch (...)
    {
    }

    return collect_state(sst, p.domain, true);
}

inline bool sanitize_spf_parameters(spf_parameters& p)
{
    string name, domain;
    if (!p.from.empty() && parse_email(p.from, name, domain))
        p.domain = domain;
    else if (p.from.empty() && p.domain.empty())
        return false;
    if (p.ip.empty())
        return false;
    return true;
}

} // namespace impl

template <class Handle>
void async_check_SPF(boost::asio::io_service& ios, const spf_parameters& pp, Handle handle)
{
    spf_parameters p = pp;
    if ( !impl::sanitize_spf_parameters(p) ) // cosher input?
    {
        handle(boost::optional<string>(), boost::optional<string>());
        return;
    }

    impl::collect_state st = impl::create_init_collect_state(ios, p);
    if (st.err)
        return;

    if (!p.from.empty())
        SPF_request_set_env_from(st.shared_state->req, p.from.c_str());
    else if (!p.domain.empty())
        SPF_request_set_helo_dom(st.shared_state->req, p.domain.c_str());
    int err = SPF_request_set_ipv4_str(st.shared_state->req, p.ip.c_str());
    if ( err != impl::SPF_E_SUCCESS)
        return;

    collect_spf_dns_data_redirect(st,
            boost::protect(
                boost::bind(impl::continue_spf_check<Handle>, _1, handle)
                )
                                  );
}

struct spf_check::spf_check_impl
{
    boost::shared_ptr<impl::collect_shared_state> shared_state;
};

spf_check::spf_check()
{
}

template <class Handler>
void spf_check::start(boost::asio::io_service& ios, const spf_parameters& pp, Handler handler)
{
    impl_.reset(new spf_check_impl);
    spf_parameters p = pp;
    if ( !impl::sanitize_spf_parameters(p) ) // cosher input?
    {
        handler(boost::optional<string>(), boost::optional<string>());
        return;
    }

    impl::collect_state st = impl::create_init_collect_state(ios, p);
    if (st.err)
    {
        handler(boost::optional<string>(), boost::optional<string>());
        return;
    }

    if (!p.from.empty())
        SPF_request_set_env_from(st.shared_state->req, p.from.c_str());
    else if (!p.domain.empty())
        SPF_request_set_helo_dom(st.shared_state->req, p.domain.c_str());
    int err = SPF_request_set_ipv4_str(st.shared_state->req, p.ip.c_str());
    if ( err != impl::SPF_E_SUCCESS)
    {
        handler(boost::optional<string>(), boost::optional<string>());
        return;
    }

    impl_->shared_state = st.shared_state;

    collect_spf_dns_data_redirect(st,
            boost::protect(
                boost::bind(impl::continue_spf_check<Handler>, _1, handler)));
}

void spf_check::stop()
{
    if (impl_ && impl_->shared_state)
    {
        impl_->shared_state->done = true;
        boost::mutex::scoped_lock lock(impl_->shared_state->mux);
        impl_->shared_state->r.cancel();
    }
    impl_.reset();
}

bool spf_check::is_inprogress() const
{
    return impl_ && impl_->shared_state && !impl_->shared_state->done;
}

#endif //ASPF_IMPL_H


