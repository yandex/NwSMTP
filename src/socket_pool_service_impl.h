#ifndef SOCKET_POOL_SERVICE_IMPL_H
#define SOCKET_POOL_SERVICE_IMPL_H

#include <boost/asio/io_service.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/basic_stream_socket.hpp>
#include <boost/unordered_map.hpp>
#include <boost/optional.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <queue>

namespace impl
{

using namespace boost;
using namespace boost::asio;

template <class Protocol, class Settings>
class socket_pool_service
        : public boost::asio::detail::service_base<socket_pool_service<Protocol, Settings> >
{
    struct wrapped_socket;

  public:
    typedef Protocol protocol_type;
    typedef typename Protocol::endpoint endpoint_type;
    typedef basic_stream_socket<Protocol> native_type;
    typedef shared_ptr<wrapped_socket> implementation_type;

  private:
    struct endpoint_hash
    {
        size_t operator()(const boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>& endpoint) const
        {
            return boost::hash_value(endpoint.address().to_v4().to_ulong());
        }
    };

    struct wrapped_socket : public enable_shared_from_this<wrapped_socket>
    {
        wrapped_socket(io_service& ios)
                : socket_(ios),
                  free_(true)
        {}

        ~wrapped_socket()
        {
            if (key_)
            {
                try {
                    socket_.close();
                } catch (...) {}
            }
        }

        inline bool is_managed() const { return key_ != 0; }

        boost::shared_ptr<wrapped_socket> next_;
        boost::weak_ptr<wrapped_socket> prev_;
        basic_stream_socket<Protocol> socket_;
        optional<endpoint_type> key_; // null if socket is not managed
        bool free_; // if the socket is managed and free_ then it is available for reuse
        time_t tm_; // connection start time

    };

    struct socket_queue // erasable queue
    {
        socket_queue()
                : sz_(0)
        {}
        size_t sz_;
        implementation_type top_;
        implementation_type bottom_;

        bool validate() // ###
        {
            if (sz_ == 0)
                return true;
            assert(top_->prev_.expired());
            assert(bottom_->next_ == 0);
            implementation_type p = top_;
            int i = sz_;
            // check forward traversal
            while (p != bottom_ && i-- > 0)
                p = p->next_;
            if (p != bottom_)
                return false;
            i = sz_;
            p = bottom_;
            // check backward traversal
            while (p != top_ && i-- > 0)
                p = implementation_type(p->prev_);
            if (p != top_)
                return false;
            return true;
        }

        implementation_type front() const
        {   return bottom_; }

        bool empty() const
        {   return sz_ == 0; }

        size_t size() const
        {   return sz_; }

        void pop()
        {
            if (--sz_ == 0)
            {
                top_.reset();
                bottom_.reset();
                return;
            }
            implementation_type tmp(bottom_->prev_);
            tmp->next_.reset();
            bottom_ = tmp;
        }

        void push(implementation_type& t)
        {
            if (++sz_ == 1)
            {
                t->next_.reset();
                t->prev_.reset();
                top_ = bottom_ = t;
                return;
            }
            top_->prev_ = t;
            t->next_ = top_;
            t->prev_.reset();
            top_ = t;
        }

        void erase(implementation_type& t)
        {
            if (--sz_ == 0)
            {
                bottom_.reset();
                top_.reset();
                return;
            }
            if (t->prev_.expired())
            {
                assert(t == top_);
                implementation_type tmp = top_->next_;
                tmp->prev_.reset();
                top_ = tmp;
                return;
            }
            if (t->next_ == 0)
            {
                assert (t == bottom_);
                implementation_type tmp(bottom_->prev_);
                tmp->next_.reset();
                bottom_ = tmp;
                return;
            }
            implementation_type nn = t->next_;
            implementation_type pp(t->prev_);
            pp->next_ = nn;
            nn->prev_ = pp;
        }
    };

    typedef std::pair<socket_queue, socket_queue> socket_queue_pair; // pair of free and reserved socket queues
    typedef boost::unordered_map<endpoint_type, socket_queue_pair, endpoint_hash> socket_map;
    socket_map socket_map_;

    mutable asio::detail::mutex mutex_;
    asio::detail::io_service_impl& io_service_impl_;

    template <typename ConstBufferSequence, typename WriteHandler>
    friend struct handle_send;

    template <typename ConstBufferSequence, typename WriteHandler>
    friend struct handle_receive;

  public:
    socket_pool_service(io_service& io_service)
            : boost::asio::detail::service_base<socket_pool_service<Protocol, Settings> >(io_service),
              mutex_(),
              io_service_impl_(use_service<asio::detail::io_service_impl>(io_service))
    {
    }

    ~socket_pool_service()
    {
        shutdown_service();
    }

    void shutdown_service()
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        socket_map_.clear();
    }

    void construct(implementation_type& impl)
    {
        // We use deferred construction
    }

    void destroy(implementation_type& impl)
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return;

        boost::system::error_code ec;
        if (impl->key_)
            do_close(impl, ec);
        else
            impl.reset();
    }

    void cancel(implementation_type& impl)
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return;
        impl->socket_.cancel();
    }

    bool is_open(const implementation_type& impl) const
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return false;
        if (impl->is_managed())
        {
            assert (impl->socket_.is_open()); // ###
            return true;
        }
        return impl->socket_.is_open();
    }

    boost::system::error_code close(implementation_type& impl,
            boost::system::error_code& ec)
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return ec = boost::system::error_code();

        if (!impl->is_managed())
            return impl->socket_.close(ec);

        if (!impl->free_)
        {
            boost::system::error_code rv = do_close(impl, ec);
            return rv;
        }
        return ec = boost::system::error_code(); // If available for reuse do nothing
    }

    native_type native(implementation_type& impl)
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            do_construct(impl);
        return impl->socket;
    }

    bool at_mark(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return false;
        return impl->socket.at_mark(ec);
    }

    std::size_t available(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return false;
        return impl->socket.available();
    }

    template <typename ConnectHandler>
    void async_connect(implementation_type& impl,
            const endpoint_type& endpoint, ConnectHandler handler)
    {
        time_t now = time(0);
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (impl && impl->is_managed()) // already in the pool?
        {
            assert(!impl->free_);
            if (now < impl->tm_ + Settings::ttl(*impl->key_))
            {
                lock.unlock();

                // dispatch the handler
                io_service_impl_.dispatch(asio::detail::bind_handler(handler,
                                boost::system::error_code()));
                return;
            }

            // time to reconnect
            try {
                impl->socket_.close();
            } catch (...) {}
            impl->tm_ = now;

            // schedule async_connect on the wrapped socket
            impl->tm_ = now;
            lock.unlock();
            impl->socket_.async_connect(endpoint, handler);

            return;
        }

        std::pair<typename socket_map::iterator, bool> v =
                socket_map_.insert(typename socket_map::value_type(endpoint,
                                socket_queue_pair()));
        socket_queue_pair& p = (v.first)->second;
        socket_queue& free_q = p.first;
        socket_queue& used_q = p.second;
        //      assert(free_q.validate()); // ###
        //      assert(used_q.validate()); // ###

        size_t max_conn = Settings::max_persistent_connections(endpoint);
        if (v.second) // new endpoint?
        {
            if (max_conn > 0)
            {
                if (!impl)
                    do_construct(impl);

                impl->key_ = endpoint;
                impl->free_ = false;
                used_q.push(impl);
                //          assert(used_q.validate()); // ###
                // schedule async_connect on the wrapped socket
                impl->tm_ = now;
                lock.unlock();
                impl->socket_.async_connect(endpoint, handler);

                return;
            }
        }
        else if (!free_q.empty()) // any free sockets for this endpoint?
        {
            // mark the socket used
            impl = free_q.front();
            free_q.pop();
            //      assert(free_q.validate()); // ###
            impl->free_ = false;
            used_q.push(impl);
            //      assert(used_q.validate()); // ###
            // dispatch the handler
            lock.unlock();
            io_service_impl_.dispatch(asio::detail::bind_handler(handler,
                            boost::system::error_code()));
            return;
        }

        // no free sockets left, check if we hit the limit on managed sockets
        if (used_q.size() >= max_conn)
        {
            if (!impl)
                do_construct(impl);

            lock.unlock();
            // the wrapped socket will remain unmanaged; schedule async_connect on it
            impl->socket_.async_connect(endpoint, handler);
            return;
        }

        if (!impl)
            do_construct(impl);

        // make the socket managed
        impl->key_ = endpoint;
        impl->free_ = false;
        used_q.push(impl);

        //      assert(used_q.validate()); // ###
        // schedule async_connect on the wrapped socket
        impl->tm_ = now;
        lock.unlock();
        impl->socket_.async_connect(endpoint, handler);

        return;
    }

    endpoint_type local_endpoint(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return ec = boost::system::error_code(asio::error::invalid_argument);
        return impl->socket.local_endpoint(ec);
    }

    endpoint_type remote_endpoint(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
            return ec = boost::system::error_code(asio::error::invalid_argument);
        return impl->socket.remote_endpoint(ec);
    }

    boost::system::error_code shutdown(implementation_type& impl,
            socket_base::shutdown_type what, boost::system::error_code& ec)
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (impl && !impl->is_managed())
            return impl->socket_.shutdown(what, ec);

        return ec = boost::system::error_code();
    }

    template <typename ConstBufferSequence, typename WriteHandler>
    struct handle_send
    {
        socket_pool_service& service;
        implementation_type& impl;
        const ConstBufferSequence& buffers;
        socket_base::message_flags flags;
        WriteHandler handler;

        void operator()(const boost::system::error_code& ec, size_t sz)
        {
            if (ec == boost::asio::error::broken_pipe)
            {
                // connection broken; remove it from the pool
                assert(!impl->free_);
                asio::detail::mutex::scoped_lock lock(service.mutex_);
                typename socket_pool_service::socket_map::iterator v =
                        service.socket_map_.find(impl->key_.get());
                typename socket_pool_service::socket_queue_pair& p = (v->second);
                typename socket_pool_service::socket_queue& used_q = p.second;
                used_q.erase(impl);
                impl->key_ = optional<endpoint_type>();
            }
            handler(ec, sz);
        }
    };

    template <typename MutableBufferSequence, typename ReadHandler>
    struct handle_receive
    {
        socket_pool_service& service;
        implementation_type& impl;
        const MutableBufferSequence& buffers;
        socket_base::message_flags flags;
        ReadHandler handler;

        void operator()(const boost::system::error_code& ec, size_t sz)
        {
            if (ec == boost::asio::error::eof)
            {
                // connection broken; remove it from the pool
                assert(!impl->free_);
                asio::detail::mutex::scoped_lock lock(service.mutex_);
                typename socket_pool_service::socket_map::iterator v =
                        service.socket_map_.find(impl->key_.get());
                typename socket_pool_service::socket_queue_pair& p = (v->second);
                typename socket_pool_service::socket_queue& used_q = p.second;
                used_q.erase(impl);
                impl->key_ = optional<endpoint_type>();
            }
            handler(ec, sz);
        }
    };

    template <typename ConstBufferSequence, typename WriteHandler>
    void async_send(implementation_type& impl,
            const ConstBufferSequence& buffers,
            socket_base::message_flags flags, WriteHandler handler)
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
        {
            io_service_impl_.dispatch(asio::detail::bind_handler(handler,
                            asio::error::not_connected, 0));
            return;
        }

        if (impl->is_managed())
        {
            handle_send<ConstBufferSequence, WriteHandler> handler_wrapper =
                    {*this, impl, buffers, flags, handler};
            impl->socket_.async_send(buffers, flags, handler_wrapper);
        }
        else
        {
            impl->socket_.async_send(buffers, flags, handler);
        }
    }

    template <typename MutableBufferSequence, typename ReadHandler>
    void async_receive(implementation_type& impl,
            const MutableBufferSequence& buffers,
            socket_base::message_flags flags, ReadHandler handler)
    {
        asio::detail::mutex::scoped_lock lock(mutex_);
        if (!impl)
        {
            io_service_impl_.dispatch(boost::asio::detail::bind_handler(handler,
                            asio::error::not_connected, 0));
            return;
        }

        if (impl->is_managed())
        {
            handle_receive<MutableBufferSequence, ReadHandler> handler_wrapper =
                    {*this, impl, buffers, flags, handler};
            impl->socket_.async_receive(buffers, flags, handler_wrapper);
        }
        else
        {
            impl->socket_.async_receive(buffers, flags, handler);
        }
    }

  private:
    inline void do_construct(implementation_type& impl)
    {
        impl.reset(new wrapped_socket(this->get_io_service()));
    }

    boost::system::error_code do_close(implementation_type& impl,
            boost::system::error_code& ec)
    {
        if (impl->free_)
        {
            impl.reset();
            return ec = boost::system::error_code();
        }

        typename socket_map::iterator v = socket_map_.find(impl->key_.get());
        assert (v != socket_map_.end());

        // mark the socket free
        socket_queue_pair& p = (v->second);
        socket_queue& free_q = p.first;
        socket_queue& used_q = p.second;
        //      assert(free_q.validate()); // ###
        //      assert(used_q.validate()); // ###
        used_q.erase(impl);
        //      assert(used_q.validate()); // ###
        if (time(0) < impl->tm_ + Settings::ttl(*impl->key_))
        {
            impl->free_ = true;
            free_q.push(impl);
        }
        else
        {
            // time to remove the socket from the pool
            impl->key_ = optional<endpoint_type>();
        }
        //      assert(free_q.validate()); // ###

        impl.reset();
        return ec = boost::system::error_code();
    }
};

} // namespace impl

#endif //SOCKET_POOL_SERVICE_IMPL_H







