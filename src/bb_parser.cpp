#include <config.h>

#ifdef ENABLE_AUTH_BLACKBOX

#include <algorithm>
#include <iterator>
#include <ostream>
#include <sstream>
#include <stdio.h>
#include <cstring>
#include <boost/bind.hpp>
#include <iostream>
#include <uti.h>

#include "bb_parser.h"

//  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
const int enc[256] = {  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 00
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 10
                        1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,  // 20
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  // 30
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 40
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  // 50
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 60
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0,  // 70
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 80
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 90
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // A0
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // B0
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // C0
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // D0
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // E0
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }; // F0

static std::string url_enc(char _ch)
{

    if (enc[(int)_ch] == 1)
    {
        char buffer[20];

        snprintf(buffer, sizeof(buffer), "%%%02x", _ch);

        return buffer;
    }
    else
    {
        return std::string(&_ch,1);
    }

}


std::string black_box_parser::url_encode(const std::string &_buffer)
{
    std::ostringstream remote_filt;

    std::transform(_buffer.begin(), _buffer.end(), std::ostream_iterator<std::string>(remote_filt), url_enc);

    return remote_filt.str();

}

bool black_box_parser::format_bb_request(request_method _method,
        const std::string &_url,
        const std::string &_login,
        const std::string &_sid,
        const std::string &_ip,
        const field_map &_req_field,
        bool _optimize,
        std::string &_request)
{
    switch (_method)
    {
        case METHOD_USER_INFO:
            _request.assign(_url + "/?method=userinfo");
            break;

        case METHOD_USER_AUTH:
            _request.assign(_url + "/?method=login");
            break;


        default:
            return false;
    }

    if (_login.empty() || _sid.empty() || _ip.empty())
        return false;

    _request.append("&login=" + _login);
    _request.append("&sid=" + _sid);
    _request.append("&userip=" + _ip);

    std::string field_list;

    for (field_map::const_iterator it = _req_field.begin(); it != _req_field.end(); it++)
    {
        if (field_list.empty())
        {
            field_list.append(it->first);
        }
        else
        {
            field_list.append("," + it->first);
        }
    }

    _request.append("&dbfields=" + field_list);

    if (!_optimize)
    {
        _request.append("&optimize=no");
    }

    return true;

}

void XMLCALL p_start_element(void* _user_data, const char* _name, const char** _atts)
{
    ((black_box_parser*)_user_data)->start_element(_name, _atts);
}

void XMLCALL p_end_element(void* _user_data, const char* _name)
{
    ((black_box_parser*)_user_data)->end_element(_name);
}

void XMLCALL p_character_data_handler(void* _user_data, const XML_Char* _str, int _len)
{
    ((black_box_parser*)_user_data)->character_data_handler(_str, _len);
}

void black_box_parser::start_parse_request(const field_map &_map)
{
    m_field_map = _map;

    m_karma = 0;
    m_karma_status = 0;
    m_ban_time = 0;
    m_uid.clear();

    m_auth_success = false;

    m_has_exception = false;

    if (m_parser)
        XML_ParserFree(m_parser);

    m_parser = XML_ParserCreate(NULL);

    XML_SetUserData(m_parser, this);

    XML_SetElementHandler(m_parser, p_start_element, p_end_element);
    XML_SetCharacterDataHandler(m_parser, p_character_data_handler);

}

void black_box_parser::start_element(const char* _name, const char** _atts)
{
    m_collect_attrs = _atts;
}

bool black_box_parser::get_attr(const char *_name, std::string &_value)
{
    for (int i = 0; m_collect_attrs[i]; i += 2)
    {
        if (strcasecmp(m_collect_attrs[i], _name) == 0)
        {
            _value = m_collect_attrs[i+1];
            return true;
        }
    }

    return false;
}

static std::string borndate2timestamp(const char* bd)
{
    struct tm tmepoch;

    memset(&tmepoch,0,sizeof tmepoch);
    int y=0,m=0,d=0;
    sscanf(bd, "%d-%d-%d", &y, &m, &d);

    tmepoch.tm_year = y - 1900;
    tmepoch.tm_mon = m - 1;
    tmepoch.tm_mday = d;
    tmepoch.tm_isdst = -1;

    std::stringstream ss;

    ss << mktime(&tmepoch);

    return ss.str();
}

static std::string regdate2timestamp(const char* rd)
{
    struct tm tmepoch;
    memset(&tmepoch,0,sizeof tmepoch);
    int y=0,mo=0,d=0, h=0, mi=0, s=0;
    sscanf(rd, "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &s);
    tmepoch.tm_year = y - 1900;
    tmepoch.tm_mon = mo - 1;
    tmepoch.tm_mday = d;
    tmepoch.tm_hour = h;
    tmepoch.tm_min = mi;
    tmepoch.tm_sec = s;
    tmepoch.tm_isdst = -1;

    std::stringstream ss;

    ss << mktime(&tmepoch);

    return ss.str();
}

void black_box_parser::end_element(const char* _name)
{

    m_collect_chars = trim(m_collect_chars);
    
    std::string nm(_name);

    if ( nm == "uid" )
    {
        m_uid = m_collect_chars;
    }
    else if (nm == "karma")
    {
        m_karma = atoi(m_collect_chars.c_str());

        std::string buffer;

        if (get_attr("confirmed", buffer))
        {
            m_karma_status = atoi(buffer.c_str());
        }
        else if (get_attr("allow-until", buffer))
        {
            m_ban_time = atoi(buffer.c_str());
        }
    }
    else if (nm == "dbfield")
    {
        std::string buffer;

        if (get_attr("id", buffer))
        {
            field_map::iterator it = m_field_map.find(buffer);

            if (it != m_field_map.end())
            {
                if (buffer == "account_info.reg_date.uid")
                {
                    it->second = regdate2timestamp(m_collect_chars.c_str());
                }
                else if (buffer == "subscription.born_date.-")
                {
                    it->second = borndate2timestamp(m_collect_chars.c_str());
                }
                else
                {
                    it->second =  m_collect_chars;
                }
            }
        }
    }
    else if (nm == "exception")
    {
        m_has_exception = true;

        std::string buffer;

        if (get_attr("id", buffer))
        {
            m_exception_code = atoi(buffer.c_str());
        }

        m_exception_name = m_collect_chars;
    }
    else if (nm == "error")
    {
//        m_has_exception = !((m_collect_chars == "OK") || (m_collect_chars == "INVALID"));
        m_error_name = m_collect_chars;
    }
    else if (nm == "status")
    {
        m_auth_success = (m_collect_chars == "VALID");
    }
    
    m_collect_chars.clear();
}

void black_box_parser::character_data_handler(const XML_Char* _str, int _len)
{
    m_collect_chars.append(_str, _len);
}

bool black_box_parser::parse_buffer(const std::string &_buffer, bool _done)
{
    return (XML_Parse(m_parser, _buffer.c_str(), _buffer.length(), _done) == XML_STATUS_OK);
}

black_box_parser::black_box_parser():
        m_parser(NULL)
{
}

black_box_parser::~black_box_parser()
{
    if (m_parser)
        XML_ParserFree(m_parser);
}

#endif // ENABLE_AUTH_BLACKBOX

