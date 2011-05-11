//
// dns_resolver_impl.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2008 Andreas Haberstroh (andreas at ibusy dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef BOOST_NET_DNS_RESOLVER_IMPL_HPP
#define BOOST_NET_DNS_RESOLVER_IMPL_HPP

#include <vector>

#include <boost/thread/mutex.hpp>
#include <boost/random.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/enable_shared_from_this.hpp>

namespace y {
namespace net {
namespace dns {

namespace {
const int def_timeout_sec = 2; // default send attempt timeout
const int def_retries = 15; // default send attempts until expiry
const int def_dns_id_gen_retries = 5; // how many times we try to generate packet id (in case of collission) by default
}

using namespace ::boost::multi_index;

struct change_time
{
    boost::posix_time::ptime t_;
    change_time(boost::posix_time::ptime t) 
            : t_(t) 
    {
    }

    template <class T>
    void operator()(T& t)
    {
        t = t_;
    }
};

class dns_resolver_impl : public boost::enable_shared_from_this<dns_resolver_impl>
{
  public: 
    typedef net::dns::resolver_iterator iterator_type;    

  private:
    /// Outbound DNS request buffer 
    typedef vector<ip::udp::endpoint> ep_vector_t;

    class dns_handler_base
    {
      public:
        dns_handler_base()
        {
        }
    
        virtual ~dns_handler_base()
        {
        }

        virtual void invoke(io_service& ios, net::dns::resolver_iterator it, const boost::system::error_code& ec)
        {}
    };

    /// Handler to wrap asynchronous callback function
    template <typename Handler>
    class dns_handler : public dns_handler_base
    {
      public:
        dns_handler(Handler h)
                : dns_handler_base(),
                  handler_(h)
        {
        }

        virtual void invoke(io_service&, net::dns::resolver_iterator iter, const boost::system::error_code& ec)
        {         
            assert( ec || iter != net::dns::resolver_iterator() );
            handler_(ec, iter);
        }
      
      private:
        Handler handler_;
    };

    typedef shared_ptr<dns_handler_base>  dns_handler_base_t;

    template <typename Handler>
    static dns_handler_base_t create_handler(Handler h)
    {   return shared_ptr<dns_handler<Handler> >(new dns_handler<Handler>(h)); }

    /*!
      DNS Query structure  
    */
    struct dns_query_t
    {
        dns_query_t(const net::dns::question& q, int retries, int timeout_sec)
                : _question(q),
                  _time(posix_time::second_clock::local_time()),
                  _retries(retries),
                  _timeout_sec(timeout_sec)
        {
        }

        bool expired(boost::posix_time::ptime now = boost::posix_time::second_clock::local_time()) const
        {
            return !boost::posix_time::time_period(_time, ttl()).contains(now);
        }

        /// How many seconds left since last resend attempt until this query is expired
        boost::posix_time::time_duration ttl() const
        {   return posix_time::seconds(_timeout_sec) * _retries;  }

        /// Question ID
        uint16_t        _question_id;
    
        /// Domain Name Server Address to send request to
        ip::udp::endpoint _dns;

        /// DNS Query Buffer
        dns_buffer_t          _mbuffer;

        /// DNS Query question
        net::dns::question                _question;
    
        /// DNS Completion handler
        dns_handler_base_t                _completion_callback;
      
        /// Time of last send attempt
        boost::posix_time::ptime _time;

        /// Number of send attempts left
        int _retries;      

        /// Timeout of a single send attempt
        int _timeout_sec;
    };

    typedef shared_ptr<dns_query_t>   shared_dq_t;

    struct by_qid{};
    struct by_time{};
#if !defined(GENERATING_DOCUMENTATION)
    typedef 
    multi_index_container<
        shared_dq_t,
        indexed_by<
        ordered_non_unique< 
        tag<by_time>,
        member<dns_query_t, posix_time::ptime, &dns_query_t::_time> 
    >,      
        hashed_unique< 
        tag<by_qid>, 
        member<dns_query_t, uint16_t, &dns_query_t::_question_id> 
    >
    >
    > query_container_t;
#endif
    typedef query_container_t::index<by_qid>::type::iterator qid_iterator_t;
    typedef query_container_t::index<by_time>::type::iterator time_iterator_t;

    io_service&       _ios;
    deadline_timer    _timer;
    ip::udp::socket   _socket;
    ep_vector_t       _dnsList;
    query_container_t _query_list;
    boost::asio::strand _strand;
    boost::mt19937 _rng;
    int _retries;
    int _timeout_sec;

  public: 
    dns_resolver_impl(io_service& ios)
            : _ios(ios),
              _timer(_ios),
              _socket(_ios, ip::udp::endpoint(ip::udp::v4(), 0)),
              _strand(_ios),
              _retries(def_retries),
              _timeout_sec(def_timeout_sec)
    {
    }

    ~dns_resolver_impl()
    {
    }
   
    void destroy()
    {
        cancel();
    }   

    void add_nameserver(ip::address addr)
    {
        ip::udp::endpoint endpoint(addr, 53);
        _dnsList.push_back(endpoint);
    }  

    void cancel()
    {
        _ios.post(
            _strand.wrap(
                boost::bind(&dns_resolver_impl::do_cancel, shared_from_this())));
    }

    template<typename Handler>
    void async_resolve(const net::dns::question& question, Handler handler)
    {  
        ep_vector_t::iterator iter = _dnsList.begin();
        if (iter == _dnsList.end())
        {
            _dnsList.push_back( ip::udp::endpoint(ip::address::from_string("127.0.0.1"), 53) );
            iter = _dnsList.begin();
        }

        shared_dq_t dq = shared_dq_t(new dns_query_t(question, _retries, _timeout_sec));
        dq->_question_id = static_cast<uint16_t> (_rng() % 65536);
        dq->_dns = *iter;
        dq->_completion_callback = create_handler(handler);
        _ios.post(
            _strand.wrap(
                boost::bind(&dns_resolver_impl::async_resolve_helper, 
                        shared_from_this(), dq)));
    }
    
    void async_resolve_helper(shared_dq_t dq)
    {
        /*      
                if (dq->expired())
                {
                iterator_type iter;
                dq->_completion_callback->invoke(_ios, 
                iter, 
                error::timed_out);
                return;
                }
        */
        int tries = def_dns_id_gen_retries;
        while (--tries
                && _query_list.get<by_qid>().find(dq->_question_id) != _query_list.get<by_qid>().end()) // id collision ?
            dq->_question_id =static_cast<uint16_t> (_rng() % 65536); // try again

        if ( !tries ) // id collision?
        {
            _ios.post(
                _strand.wrap(
                    boost::bind(                                    
                        &dns_resolver_impl::async_resolve_helper, 
                        shared_from_this(), dq))); // well, maybe later
            return;
        }

        net::dns::message m(dq->_question);
        m.recursive(true);
        m.action(net::dns::message::query);
        m.opcode(net::dns::message::squery);
        m.id(dq->_question_id);
        m.encode(dq->_mbuffer);

        _query_list.insert(dq);
        send_request(dq);     

        posix_time::time_duration ted = _timer.expires_from_now();
        posix_time::time_duration nt = posix_time::seconds(_timeout_sec);
        if (ted.is_special() || ted > nt)  // timer not already set ?
        {
            _timer.expires_from_now(nt);
            _timer.async_wait(
                _strand.wrap(
                    boost::bind(
                        &dns_resolver_impl::handle_timeout, 
                        shared_from_this(),
                        boost::asio::placeholders::error)));
        }
    }

    template<typename Handler>
    void async_resolve(const string & domain, const net::dns::type_t rrtype, Handler handler)
    {
        net::dns::question question(domain, rrtype);
        async_resolve(question, handler);
    }

    boost::asio::io_service & get_io_service()
    {
        return _ios;
    }
  
  private:
    void do_cancel()
    {
        try {
            _timer.cancel();
            //    _socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            _socket.close();    
        } catch (...) {}
 
        for (time_iterator_t it = _query_list.get<by_time>().begin(); 
             it != _query_list.get<by_time>().end(); )
        {
            time_iterator_t saved = it++;
            iterator_type iter;   
            assert(*saved);
            (*saved)->_completion_callback->invoke(_ios, iter, boost::asio::error::operation_aborted);
            _query_list.erase(saved);
        }
        assert(_query_list.empty());
    }

    void send_request(shared_dq_t dq)
    {
        qid_iterator_t qid_it = _query_list.get<by_qid>().find(dq->_question_id);
        if (qid_it == _query_list.get<by_qid>().end()) // query already processed      
            return;      
        time_iterator_t time_it = _query_list.project<by_time>(qid_it);
        boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
        _query_list.get<by_time>().modify_key(time_it, change_time(now));


        if( !_socket.is_open() )
            _socket.open(ip::udp::v4());      

        _socket.async_send_to(
            boost::asio::buffer(
                dq->_mbuffer.data(), 
                dq->_mbuffer.length()
                ), 
            dq->_dns, _strand.wrap(boost::bind(
                &dns_resolver_impl::handle_send, 
                shared_from_this(), dq,
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred))
            );
    }
  
    void handle_send(shared_dq_t dq, const boost::system::error_code& ec, size_t bytes_sent)
    {
        if (!ec && _socket.is_open())
        {
            shared_dns_buffer_t rbuffer(new dns_buffer_t );
            _socket.async_receive(
                boost::asio::buffer( *(rbuffer.get())), 
                _strand.wrap(boost::bind(
                    &dns_resolver_impl::handle_recv, 
                    shared_from_this(), 
                    rbuffer, boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred))
                );
        }
        else if (ec != boost::asio::error::operation_aborted)
        {
            qid_iterator_t qid_it = _query_list.get<by_qid>().find(dq->_question_id);
            if (qid_it == _query_list.get<by_qid>().end()) // query already processed      
                return;
            iterator_type iter;
            dq->_completion_callback->invoke(_ios, iter, ec);
            _query_list.get<by_qid>().erase(qid_it);
            if (_query_list.empty())
                do_cancel();
        }
    }

    void handle_recv(shared_dns_buffer_t inBuffer, const boost::system::error_code& ec, std::size_t bytes_transferred)
    {    
        if (!ec && bytes_transferred)
        {       
            inBuffer.get()->length(bytes_transferred);

            net::dns::message  tmpMessage;
      
            uint16_t  qid;
            inBuffer.get()->get(qid); 

            qid_iterator_t qid_it = _query_list.get<by_qid>().find(qid);
            if (qid_it == _query_list.get<by_qid>().end()) // query already processed     
                return ;      
            shared_dq_t dq = *qid_it;
            _query_list.get<by_qid>().erase(qid_it);
            if (_query_list.empty())
                do_cancel();      

            tmpMessage.decode( *inBuffer.get() );      

            if ( tmpMessage.result() == net::dns::message::noerror
                    && tmpMessage.answers()->size() )
            {
                iterator_type iter = iterator_type::create(*tmpMessage.answers(), dq->_question.rtype());
                if (iter != iterator_type())
                {
                    dq->_completion_callback->invoke( _ios, iter, boost::system::error_code() );
                    return;
                }
            }
            dq->_completion_callback->invoke( _ios, iterator_type(), error::not_found );            
        }
    }

    void handle_timeout(const boost::system::error_code& ec)
    {
        if( !ec )
        {      
            posix_time::ptime now = boost::posix_time::second_clock::local_time();
            posix_time::time_duration nt = boost::posix_time::seconds(_timeout_sec);
            if (_query_list.size())
            {   
                boost::posix_time::ptime margin = now - boost::posix_time::seconds(_timeout_sec);
                time_iterator_t it = _query_list.get<by_time>().begin();
                while (it != _query_list.get<by_time>().end())
                {
                    if ((*it)->_time > margin)
                    {
                        nt = (*it)->_time - margin;
                        break;
                    }
                    time_iterator_t saved = it++;
                    if (--((*saved)->_retries) > 0)
                    {
                        shared_dq_t dq = *saved;
                        send_request(dq);
                    }
                    else
                    {           
                        iterator_type iter;
                        (*saved)->_completion_callback->invoke(
                            _ios, iter, error::timed_out);
                        _query_list.get<by_time>().erase(saved);
                    }   
                }
            }
            
            if (_query_list.size())
            {     
                _timer.expires_from_now(nt);
                _timer.async_wait(
                    _strand.wrap(
                        boost::bind(
                            &dns_resolver_impl::handle_timeout, 
                            shared_from_this(),
                            boost::asio::placeholders::error))
                    );
            }
        }
    }
};

} // namespace dns
} // namespace net
} // namespace y

#endif  // BOOST_NET_DNS_RESOLVER_IMPL_HPP
