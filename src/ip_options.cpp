#include <fstream>
#include <iomanip>
#include <iostream>
#include <boost/tokenizer.hpp>
#include <list>
#include "ip_options.h"


ip_options_config g_ip_config;

ip_options_config::ip_options_config()
{
}

bool ip_options_config::load(const std::string _file)
{

    std::ifstream file(_file.c_str());

    if (!file.good())
        return false;

    std::string buffer;

    while(!std::getline(file, buffer).eof())
    {

        std::string::size_type pos = buffer.find_first_not_of(" \t");

        if (pos == std::string::npos)
            continue;

        buffer = buffer.substr(pos);

        if ((!buffer.empty()) && (buffer[0] == '#'))
            continue;

        pos = buffer.find("/");
        std::string::size_type pos2 = buffer.find_first_of(" \t");

        if (pos2 == std::string::npos)  // not space to end of line
        {
            continue;
        }

        std::string ip;
        std::string mask("32");

        if (pos == std::string::npos)
        {
            ip = buffer.substr(0, pos2);                // single ip from start of line
            buffer = buffer.substr(pos2);
        }
        else
        {
            ip = buffer.substr(0, pos);                         // ip/mask in CIDR
            mask =  buffer.substr(pos+1, pos2 - pos);

            buffer = buffer.substr(pos2+1);
        }

        opt_store_t opt;

        try
        {
            opt.m_network = boost::asio::ip::address_v4::from_string(ip).to_ulong();

            int cnt = atoi(mask.c_str());

            if ((cnt < 0) || (cnt > 32))
            {
                continue;
            }

            unsigned int msk = 0;

            for(int i = 1; i <= cnt; i++)
            {
                msk |= 1 << (32-i);
            }

            opt.m_mask = msk;
        }
        catch(...)
        {
            continue;
        }

        typedef boost::tokenizer<boost::char_separator<char> > tokenizer;

        boost::char_separator<char> sep(" \t");
        tokenizer tokens(buffer, sep);

        if (std::distance(tokens.begin(), tokens.end()) < 1)
        {
            continue;
        }

        tokenizer::iterator tok_iter = tokens.begin();

        opt.m_options.m_rcpt_count = atoi(tok_iter->c_str());           // rcpt count

        m_opt_list.push_back(opt);
    }

    return true;
}

struct pred
{
    pred(const boost::asio::ip::address_v4 &_address)
    {
        m_address = _address;
    }

    bool operator () (const ip_options_config::opt_store_t &_opt)
    {

        /*      unsigned int a = m_address.to_ulong();
                unsigned int b = _opt.m_mask;
                unsigned int c = _opt.m_network;

                std::cout << std::hex << "a=" << a << " b=" << b << " c=" << c << " and=" << (a&b) << std::endl;*/


        return ((m_address.to_ulong() & _opt.m_mask) == (_opt.m_network & _opt.m_mask));
    }

    boost::asio::ip::address_v4 m_address;
};

bool ip_options_config::check(const boost::asio::ip::address_v4 _address, ip_options_t &_options)
{
    opt_store_list::iterator it = std::find_if(m_opt_list.begin(), m_opt_list.end(), pred(_address));

    if (it != m_opt_list.end())
    {
        _options = it->m_options;
        return true;
    }

    return false;
}

