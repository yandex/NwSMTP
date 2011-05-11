#if !defined(_UTI_H_)
#define _UTI_H_

#include <string>
#include <boost/asio.hpp>

std::string trim(const std::string &_str); // smtp_connection.cpp

std::string cleanup_str(const std::string &_str);

std::string rev_order_av4_str(const boost::asio::ip::address_v4&, const std::string& domain);

std::string unfqdn(const std::string& fqdn); // remove last dot from fqdn, if any

unsigned long djb2_hash(const unsigned char* str, size_t size);

inline bool parse_email(const std::string& email, std::string& name, std::string& domain)
{
    if (const char* at = strchr(email.c_str(), '@'))
    {
        name = std::string(email.c_str(), at);
        domain = std::string(at+1, email.c_str() + email.size());
        return true;
    }
    return false;
}

#endif //_UTI_H_
