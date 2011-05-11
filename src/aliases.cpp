#include <fstream>
#include <iostream>
#include <boost/thread/locks.hpp>
#include <boost/format.hpp>

#include "aliases.h"
#include "log.h"


aliases g_aliases;

aliases::aliases()
{
}

bool aliases::load(const std::string &_file_name)
{
    std::ifstream file(_file_name.c_str());

    if (!file.good())
        return false;

    std::map<std::string, std::list< std::string > > new_aliases;

    std::string buffer;

    while(!std::getline(file, buffer).eof())
    {

        std::string::size_type pos = buffer.find_first_of(" \t");

        if (pos == std::string::npos)
            continue;

        std::string key = buffer.substr(0, pos);

        std::transform(key.begin(), key.end(), key.begin(), ::tolower);

        std::string al = buffer.substr(pos+1);

        std::list<std::string> values;

        while (al.length() > 0)
        {

            std::string::size_type comma_pos = al.find(",");

            std::string next;

            if (comma_pos == std::string::npos)
            {
                next = al;
                al.clear();
            }
            else
            {
                next = al.substr(0, comma_pos);
                al = al.substr(comma_pos + 1 );
            }

            std::string::size_type start = next.find_first_not_of(" \t");

            if (start == std::string::npos)
            {
                start = 0;
            }

            std::string::size_type end = next.find_last_not_of(" \t");

            if (end == std::string::npos)
            {
                end = next.length();
            }

            values.push_back(next.substr(start, (end-start)+1));

        }

        new_aliases[key] = values;
    }

    boost::unique_lock<boost::shared_mutex> lck(m_mutex);

    m_aliases.swap(new_aliases);

    return true;

}

bool aliases::process(const std::string &_rcpt, const long long unsigned _suid,  boost::function< void (const std::string&, long long unsigned) > _func)
{
    boost::shared_lock<boost::shared_mutex> lck(m_mutex);

    std::string lrcpt(_rcpt);

    std::transform(lrcpt.begin(), lrcpt.end(), lrcpt.begin(), ::tolower);

    std::map<std::string, std::list< std::string > >::iterator it= m_aliases.find(lrcpt);

    bool have_alias = (it != m_aliases.end());

    if (have_alias)
    {
        for(std::list< std::string>::iterator lit = it->second.begin(); lit != it->second.end(); lit++)
        {
            _func(*lit, 0);             // alias not user
        }
    }
    else
    {
        _func(_rcpt, _suid);
    }

    return have_alias;
}

