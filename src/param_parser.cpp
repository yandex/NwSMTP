#include "param_parser.h"
#include <algorithm>
#include <iostream>


std::string extract_word(std::string &_str)
{
    std::string::size_type begin = _str.find_first_not_of(" \r\n\r");

    if (begin == std::string::npos)
    {
        _str.erase(0, begin);
        return "";
    }

    std::string::size_type end = _str.find_first_of(" \t\r\n", begin);

    if (end == std::string::npos)
    {
        end = _str.length();
    }

    std::string tmp = _str.substr(begin, end - begin);

    _str.erase(0, end);

    return tmp;
}

param_parser::params_map::value_type parse_one_parameter(const std::string &_buffer)
{

    std::string::size_type pos = _buffer.find("=");

    if (pos == std::string::npos)
    {
        throw std::exception();
    }

    std::string key = _buffer.substr(0, pos);
    std::string value = _buffer.substr(pos+1);

    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    return param_parser::params_map::value_type(key, value);
}

void param_parser::parse(const std::string &_src, std::string &_addr, params_map &_params)
{
    std::string buffer(_src);

    _addr = extract_word(buffer);

    std::string param;

    while (!buffer.empty() && !(param = extract_word(buffer)).empty())
    {
        try
        {
            _params.insert(parse_one_parameter(param));
        }
        catch(...)
        {
            continue;
        }
    }
}

