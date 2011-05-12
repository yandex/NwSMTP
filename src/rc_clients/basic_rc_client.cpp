#include "basic_rc_client.h"

class basic_rc_category_t : public boost::system::error_category
{
  public:
    const char* name() const
    {
        return "nwsmtp.basic_rc";
    }

    std::string message(int value) const
    {
        if (value == bad_response_id)
            return "Bad rcsrv reponse ID";
        if (value == bad_response)
            return "Bad rcsrv response";
        return "nwsmtp.basic_rc error";
    }
};

const boost::system::error_category& get_basic_rc_category()
{
    static basic_rc_category_t instance;
    return instance;
}
