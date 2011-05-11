#if !defined(_AUTH_H_)
#define _AUTH_H_

#include <string>

class auth
{
  public:

    typedef enum
    {
        AUTH_OK = 1,    // Operation succesed
        AUTH_MORE,              // Auth need next stage
        AUTH_DONE,              // Oparation done - can start BB Request
        AUTH_FORM               // Invalid parametres
    } auth_status_t;

    typedef enum
    {
        METHOD_INVALID = 0,
        METHOD_PLAIN,
        METHOD_LOGIN
    } auth_method_t;

    auth_status_t initialize(const std::string &_ip);           // set session ip

    auth_status_t first(const std::string &_method, const std::string &_response, std::string &_reply);         // start auth operation

    auth_status_t next(const std::string &_response, std::string &_reply);                      // continue operation

    auth_status_t get_session_params(std::string &_user, std::string &_password, std::string &_ip, std::string &_method);             // set session parameters

    std::string get_methods();                  // return method parameters

  protected:

    auth_method_t method_;

    std::string username_;
    std::string password_;
    std::string ip_;
};


#endif // _AUTH_H_
