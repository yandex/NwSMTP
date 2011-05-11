#include "atormoz.h"

boost::optional<rc_result> parse_rc_response(const boost::asio::streambuf& buf)
{
    typedef boost::asio::streambuf::const_buffers_type const_buffers_type;
    typedef boost::asio::buffers_iterator<const_buffers_type> iterator;
    const_buffers_type buffers = buf.data();
    iterator begin = iterator::begin(buffers);
    iterator end = iterator::end(buffers);

    // Look for the start of the body of the response
    boost::iterator_range<const char*> delim = boost::as_literal("\r\n\r\n");
    std::pair<iterator, bool> result = boost::asio::detail::partial_search(
        begin, end, delim.begin(), delim.end());
    if (result.first != end && result.second)
    {
        iterator start = result.first + delim.size();

        // Skip a line
        delim = boost::as_literal("\r\n");
        result = boost::asio::detail::partial_search(start, end,
                delim.begin(), delim.end());
        if (result.first != end && result.second)
        {
            // todo: we can optimise parsing here
            std::string d;
            start = result.first + delim.size();
            std::copy(start, end, std::back_inserter(d));

            rc_result res;
            try
            {
                std::istringstream iss(d);
                iss >> res.ok;
                iss >> res.sum1;
                iss >> res.sum2;
                iss >> res.sum3;
                iss >> res.sum4;
            }
            catch (...)
            {
                return boost::optional<rc_result>();
            }

            return boost::optional<rc_result>(res);
        }
    }

    // No match. The response is invalid.
    return boost::optional<rc_result>();
}
