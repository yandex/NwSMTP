#ifndef ASPF_H
#define ASPF_H

#include <boost/asio.hpp>
#include <string>

struct spf_parameters
{
    std::string ip;
    std::string domain;
    std::string from;
};

template <class Handle>
void async_check_SPF(boost::asio::io_service& ios, const spf_parameters& p, Handle handle);

class spf_check
{
    struct spf_check_impl;
    boost::shared_ptr<spf_check_impl> impl_;

  public:
    spf_check();

    template <class Handle>
    void start(boost::asio::io_service& ios, const spf_parameters& p, Handle handle);

    void stop();

    bool is_inprogress() const;
};

#include "aspf_impl.h"

#endif //ASPF_H
