#ifndef SOCKET_POOL_SERVICE_H
#define SOCKET_POOL_SERVICE_H

#include <boost/asio/io_service.hpp>
#include <boost/asio/socket_base.hpp>
#include "socket_pool_service_impl.h"

template <class Protocol>
class basic_socket_pool_service_settings
{
  public:
    /// Default maximum of pooled connections per endpoint
    static size_t max_persistent_connections(const typename Protocol::endpoint&)
    {    return 20;    }

    /// Default pooled connection lifetime in seconds
    static long ttl(const typename Protocol::endpoint&)
    {    return 300; }
};

template <class Protocol, class Settings = basic_socket_pool_service_settings<Protocol> >
class socket_pool_service
        : public boost::asio::detail::service_base<socket_pool_service<Protocol, Settings> >

{
    typedef impl::socket_pool_service<Protocol, Settings> service_impl_type;

  public:
    typedef Protocol protocol_type;
    typedef typename Protocol::endpoint endpoint_type;
    typedef typename service_impl_type::implementation_type implementation_type;
    typedef typename service_impl_type::native_type native_type;

    explicit socket_pool_service(boost::asio::io_service& io_service)
            : boost::asio::detail::service_base<socket_pool_service<Protocol, Settings> >(io_service),
              service_impl_(boost::asio::use_service<service_impl_type>(io_service))
    {
    }

    boost::system::error_code open(implementation_type& impl,
            const protocol_type& protocol, boost::system::error_code& ec)
    {
        if (protocol.type() == SOCK_STREAM)
            ;
        else
            ec = boost::asio::error::invalid_argument;
        return ec;
    }

    boost::system::error_code assign(implementation_type& impl,
            const protocol_type& protocol, const native_type& native_socket,
            boost::system::error_code& ec)
    {
        return ec = boost::asio::error::operation_not_supported;
    }

    bool is_open(const implementation_type& impl) const
    {
        return service_impl_.is_open(impl);
    }

    boost::system::error_code close(implementation_type& impl,
            boost::system::error_code& ec)
    {
        return service_impl_.close(impl, ec);
    }

    native_type native(implementation_type& impl)
    {
        return service_impl_.native(impl);
    }

    bool at_mark(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        return service_impl_.at_mark(impl, ec);
    }

    std::size_t available(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        return service_impl_.available(impl, ec);
    }

    boost::system::error_code bind(implementation_type& impl,
            const endpoint_type& endpoint, boost::system::error_code& ec)
    {
        return ec = boost::asio::error::operation_not_supported;
    }

    boost::system::error_code connect(implementation_type& impl,
            const endpoint_type& peer_endpoint, boost::system::error_code& ec)
    {
        return ec = boost::asio::error::operation_not_supported;
    }

    template <typename ConnectHandler>
    void async_connect(implementation_type& impl,
            const endpoint_type& peer_endpoint, ConnectHandler handler)
    {
        service_impl_.async_connect(impl, peer_endpoint, handler);
    }

    template <typename SettableSocketOption>
    boost::system::error_code set_option(implementation_type& impl,
            const SettableSocketOption& option, boost::system::error_code& ec)
    {
        return ec = boost::asio::error::operation_not_supported;
    }

    template <typename GettableSocketOption>
    boost::system::error_code get_option(const implementation_type& impl,
            GettableSocketOption& option, boost::system::error_code& ec) const
    {
        return ec = boost::asio::error::operation_not_supported;
    }

    template <typename IoControlCommand>
    boost::system::error_code io_control(implementation_type& impl,
            IoControlCommand& command, boost::system::error_code& ec)
    {
        return ec = boost::asio::error::operation_not_supported;
    }

    endpoint_type local_endpoint(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        return service_impl_.local_endpoint(impl, ec);
    }

    endpoint_type remote_endpoint(const implementation_type& impl,
            boost::system::error_code& ec) const
    {
        return service_impl_.remote_endpoint(impl, ec);
    }

    boost::system::error_code shutdown(implementation_type& impl,
            boost::asio::socket_base::shutdown_type what, boost::system::error_code& ec)
    {
        return service_impl_.shutdown(impl, what, ec);
    }

    template <typename ConstBufferSequence>
    std::size_t send(implementation_type& impl,
            const ConstBufferSequence& buffers,
            boost::asio::socket_base::message_flags flags, boost::system::error_code& ec)
    {
        return ec = boost::asio::error::operation_not_supported;
    }

    template <typename ConstBufferSequence, typename WriteHandler>
    void async_send(implementation_type& impl,
            const ConstBufferSequence& buffers,
            boost::asio::socket_base::message_flags flags, WriteHandler handler)
    {
        service_impl_.async_send(impl, buffers, flags, handler);
    }

    template <typename MutableBufferSequence>
    std::size_t receive(implementation_type& impl,
            const MutableBufferSequence& buffers,
            boost::asio::socket_base::message_flags flags, boost::system::error_code& ec)
    {
        //      return service_impl_.receive(impl, buffers, flags, ec);
        return ec = boost::asio::error::operation_not_supported;
    }

    template <typename MutableBufferSequence, typename ReadHandler>
    void async_receive(implementation_type& impl,
            const MutableBufferSequence& buffers,
            boost::asio::socket_base::message_flags flags, ReadHandler handler)
    {
        service_impl_.async_receive(impl, buffers, flags, handler);
    }

    void shutdown_service()
    {
        service_impl_.shutdown_service();
    }

    void construct(implementation_type& impl)
    {
        service_impl_.construct(impl);
    }

    void destroy(implementation_type& impl)
    {
        service_impl_.destroy(impl);
    }

    void cancel(implementation_type& impl, boost::system::error_code&)
    {
        service_impl_.cancel(impl);
    }

  private:
    service_impl_type& service_impl_;
};

#endif // SOCKET_POOL_SERVICE_H
