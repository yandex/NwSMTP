#if !defined(_PARAM_PARSER_H_)
#define _PARAM_PARSER_H_

#include <map>
#include <string>

struct param_parser
{
    typedef std::map<std::string, std::string> params_map;

    static void parse(const std::string &_src, std::string &_addr, params_map &_params);
};
#endif //_PARAM_PARSER_H_

