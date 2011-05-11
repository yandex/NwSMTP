#include <cstring>
#include <iostream>

#include "auth.h"
#include "yplatform/base64.h"

auth::auth_status_t auth::initialize(const std::string &_ip)
{
    ip_ = _ip;

    username_.clear();
    password_.clear();

    return AUTH_OK;
}

static void extract_base64_str(const std::string &_src, std::string &_dst)
{
    _dst.reserve (_src.length() * 3 / 4);
    std::back_insert_iterator<std::string> out_iter (_dst);

    yplatform::service::base64::decoder base64;
    base64.decode (_src.begin(), _src.end(), out_iter);
}

static bool extract_user_password(const std::string &_src, std::string &_user, std::string &_password)
{
    std::string decoded;

    extract_base64_str(_src, decoded);

    std::string::size_type first_pos = decoded.find('\0');

    if (first_pos != std::string::npos)
    {
        std::string::size_type second_pos = decoded.find('\0', first_pos + 1);

        if (second_pos != std::string::npos)
        {
            _user = decoded.substr(first_pos + 1, second_pos - first_pos - 1);
            _password = decoded.substr(second_pos + 1);                         // user and password, no extra steps

            return true;
        }
        else
        {
            _user = decoded.substr(second_pos + 1);
            _password.clear();                                  // only user no password need second SASL step
            return true;
        }

    }
    else                // no start \0 fail
    {
        return false;
    }

}

auth::auth_status_t auth::first(const std::string &_method, const std::string &_init, std::string &_reply)
{
    if (strcasecmp(_method.c_str(), "plain") == 0)
    {
        method_ = METHOD_PLAIN;

        if (_init.empty())
        {
            _reply = "334 VXNlcm5hbWU6\r\n";
            return AUTH_MORE;
        }

        if (extract_user_password(_init, username_, password_))
        {
            return (username_.empty() || password_.empty()) ? AUTH_FORM : AUTH_DONE;
        }
        else
        {
            return AUTH_FORM;                                           // Inavid base64
        }
    }
    else if (strcasecmp(_method.c_str(), "login") == 0)
    {
        method_ = METHOD_LOGIN;

        if (!_init.empty())
        {
    	    extract_base64_str(_init, username_);

            _reply = "334 UGFzc3dvcmQ6\r\n";

            return username_.empty() ? AUTH_FORM : AUTH_MORE;
        }
        else
        {
    	    _reply = "334 VXNlcm5hbWU6\r\n";                                // username
    	}

        return AUTH_MORE;
    }

    return AUTH_FORM;
}

auth::auth_status_t auth::next(const std::string &_response, std::string &_reply)
{
    switch (method_)
    {
        case METHOD_PLAIN:
        
            if (extract_user_password(_response, username_, password_))
            {
        	
                return (username_.empty() || password_.empty()) ? AUTH_FORM : AUTH_DONE;
            }
            else
            {
                return AUTH_FORM;
            }

            break;

        case METHOD_LOGIN:
        
            if (username_.empty())
            {
                extract_base64_str(_response, username_);
                _reply = "334 UGFzc3dvcmQ6\r\n";
                return (username_.empty()) ? AUTH_FORM : AUTH_MORE;
            }
            else
            {
                extract_base64_str(_response, password_);
                return (password_.empty()) ? AUTH_FORM : AUTH_DONE;
            }

            break;

        case METHOD_INVALID:
        
            return AUTH_FORM;

            break;
    }
    return AUTH_OK;
}

auth::auth_status_t auth::get_session_params(std::string &_user, std::string &_password, std::string &_ip, std::string &_method)
{
    _user = username_;
    _password = password_;
    _ip = ip_;
    
    switch (method_)
    {
	case METHOD_PLAIN: 
	    _method = "PLAIN";
	    break;
	    
	case METHOD_LOGIN:
	    _method = "LOGIN";
	    break;
	    
	default:
	    _method = "INVALID";
	    break;
    }

    return AUTH_OK;
}

std::string auth::get_methods()
{
    return "LOGIN PLAIN";
}

