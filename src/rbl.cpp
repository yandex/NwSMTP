#include <iostream>
#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "uti.h"
#include "rbl.h"

using namespace y::net;


rbl_check::rbl_check(boost::asio::io_service& _io_service):
        m_resolver(_io_service)
{
}

void rbl_check::add_rbl_source(const std::string &_host_name)
{
    m_source_list.push_back(_host_name);
}

void rbl_check::start(const boost::asio::ip::address_v4 &_address, complete_cb _callback)
{
    m_complete = _callback;

    if (m_source_list.empty())
    {
        m_message.clear();
        m_resolver.get_io_service().post(m_complete);

        return;
    }

    m_current_source = m_source_list.begin();

    m_address = _address;

    start_resolve(m_address, *m_current_source);
}

void rbl_check::start_resolve(const boost::asio::ip::address_v4& av4, const std::string& d)
{
    m_resolver.async_resolve(
        rev_order_av4_str(av4, d),
        dns::type_a,
        boost::bind(&rbl_check::handle_resolve,
                shared_from_this(), _1, _2)
        );
}

void rbl_check::handle_resolve(const boost::system::error_code& ec, dns::resolver::iterator)
{
    if (!ec)
    {
        m_message = str(boost::format("554 5.7.1 Service unavailable; Client host [%1%] blocked using %2%; Blocked by spam statistics - see http://feedback.yandex.ru/?from=mail-rejects&subject=%3%\r\n")
                % m_address.to_string() %  *m_current_source % m_address.to_string());

        m_resolver.get_io_service().post(m_complete);
        m_complete.clear();
    }
    else
    {
        m_current_source ++;

        if (m_current_source == m_source_list.end())
        {
            m_message.clear();
            m_resolver.get_io_service().post(m_complete);
            m_complete.clear();
        }
        else
        {
            start_resolve(m_address, *m_current_source);
        }
    }
}

void rbl_check::stop()
{
    m_resolver.cancel();
}

bool rbl_check::get_status(std::string &_message)
{
    _message = m_message;

    return !m_message.empty();
}
