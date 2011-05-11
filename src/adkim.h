#ifndef ADKIM_H
#define ADKIM_H

#include "buffers.h"
#include <boost/function.hpp>
#include <boost/asio.hpp>

struct dkim_parameters
{
    typedef ybuffers_iterator<ystreambuf::const_buffers_type> yconst_buffers_iterator;

    yconst_buffers_iterator b;
    yconst_buffers_iterator bs;
    yconst_buffers_iterator e;

    dkim_parameters(const yconst_buffers_iterator& beg,
            const yconst_buffers_iterator& body_beg, const yconst_buffers_iterator& end)
            :  b(beg), bs(body_beg), e(end)
    {}
};

class dkim_check
{
  public:
    struct dkim_check_impl;
    enum DKIM_STATUS
    {
        DKIM_PASS,
        DKIM_NEUTRAL,
        DKIM_FAIL,
        DKIM_NONE
    };

    typedef boost::function< void (DKIM_STATUS, const std::string& indentity) > handler_t;

    dkim_check();

    void start(boost::asio::io_service& ios, const dkim_parameters& p, handler_t handler);

    void stop();

    bool is_inprogress() const;

    static const char* status(DKIM_STATUS s);

  private:
    boost::shared_ptr<dkim_check_impl> impl_;
};


#endif // ADKIM_H
