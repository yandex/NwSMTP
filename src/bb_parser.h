#if !defined(_BB_PARSER_H_)
#define _BB_PARSER_H_

#include <config.h>

#ifdef ENABLE_AUTH_BLACKBOX

#include <string>
#include <map>
#include <expat.h>

const long long unsigned int g_no_spam_uid =  56218725;
const int g_time_treshold =  10;

class black_box_parser
{
  public:

    typedef std::map<std::string, std::string> field_map;

    typedef enum {
        METHOD_USER_INFO        =       1,
        METHOD_USER_AUTH        =       2
    } request_method;

    black_box_parser();
    ~black_box_parser();

    static std::string url_encode(const std::string &_str);

    static bool format_bb_request(request_method _method,
            const std::string &_url,
            const std::string &_login,
            const std::string &_sid,
            const std::string &_ip,
            const field_map &_req_field,
            bool _optimize,
            std::string &_request);

    void start_parse_request(const field_map &_map);

    bool parse_buffer(const std::string &_buffer, bool _done); // true if ok

    void start_element(const char* _name, const char** _atts);
    void end_element(const char* _name);
    void character_data_handler(const XML_Char* _str, int _len);
    bool get_attr(const char *_name, std::string &_value);

    int m_karma;
    int m_karma_status;
    time_t m_ban_time;
    std::string m_uid;
    field_map m_field_map;

    bool m_has_exception;
    unsigned int m_exception_code;
    std::string m_exception_name;
    std::string m_error_name;

    bool m_auth_success;

  protected:

    std::string m_collect_chars;
    const char **m_collect_attrs;

    XML_Parser m_parser;
};

#endif // ENABLE_AUTH_BLACKBOX

#endif
