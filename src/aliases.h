#if !defined(_ALIASES_H_)
#define _ALIASES_H_

#include <string>
#include <list>
#include <iterator>
#include <map>
#include <boost/thread.hpp>
#include <boost/function.hpp>

class aliases
{
  public:

    aliases();

    bool load(const std::string &_file_name);

    bool process(const std::string &_rcpt, long long unsigned _suid,  boost::function< void (const std::string &, long long unsigned) >);               //true if have alias

  protected:

    std::map<std::string, std::list< std::string > > m_aliases;

    boost::shared_mutex  m_mutex;

};


extern aliases g_aliases;

#endif // _ALIASES_H_
