//
// rfc1035_414.hpp
// ~~~~~~~~~~~~~~~
//
// Copyright (c) 1998-2006 Andreas Haberstroh (andreas at ibusy dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_NET_RFC1035_414_HPP
#define BOOST_NET_RFC1035_414_HPP

#include <boost/asio/detail/push_options.hpp>

#include <vector>
#include <string>
#include <map>

#include <boost/tokenizer.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/cstdint.hpp>
#include <net/network_array.hpp>


using namespace std;
using namespace boost;

namespace y {
namespace net {

typedef network_array<576> dns_buffer_t;

/*!
  The rfc1035_414_t class is a helper class for dealing with DNS label compression inside
  of DNS type packets. This class takes its name after RFC1035, section 4.1.4.
*/
class rfc1035_414_t
{
  private:
    /*!
      The domain_offset_map_t links buffer offsets to strings for the DNS label compression
      requirements.
    */
    typedef std::map<string,size_t>   domain_offset_map_t;
      
    domain_offset_map_t _offsets;
        
  public:
    /// Default constructor
    rfc1035_414_t()
    {
    }

    /// Copy constructor
    rfc1035_414_t(const rfc1035_414_t& rfc)
            : _offsets(rfc._offsets)
    {
    }

    /// Assignment operator
    const rfc1035_414_t& operator=(const rfc1035_414_t& rfc)
    {
        _offsets = rfc._offsets;
        return *this;
    }

    /*!
      Breaks apart a domain name into it's label or compressed offset values and 
      writes it to the buffer

      \param domain Domain string to break apart into labels
      \param buffer Memory buffer to write the labels to

      \returns Number of bytes written
    */
    const size_t write_label(const string& domain, dns_buffer_t & buffer)
    {
        // no length? no service
        if( !domain.length() )
            return 0;

        // total length of the data written.
        size_t  length(0);

        // place to begin the substring at
        string::size_type begin(0);

        bool  done = false;
        while( !done )
        {
            // find the next '.' and cut the subdomain string from it.
            string::size_type current = domain.find('.', begin);
            string  subdomain( domain.substr(begin) );

            // get the length of this label
            uint8_t l( (uint8_t)(current - begin) );
            if( current == string::npos )
            {
                l = (uint8_t)subdomain.length();
                done = true;
            }

            // somehow we've read a blank label!
            if( !l ) break;

            // current domain label
            string  label( domain.substr(begin, l) );

            // deja vous?
            domain_offset_map_t::iterator iter = _offsets.find( subdomain );
            if( iter == _offsets.end() )
            {
                // save the position in the buffer
                _offsets[ subdomain ] = buffer.position();

                buffer.put( (uint8_t)label.length() );
                buffer.put( label, label.length() );
                length += sizeof(uint8_t) + label.length();
                begin = current + 1;
            }
            else
            {
                // compresses reference
                size_t  offset = (0xC000 | iter->second);
                buffer.put( (uint8_t)(offset >> 8) );
                buffer.put( (uint8_t)(offset) );

                // every byte counts
                length += sizeof(uint16_t);
                return length;
            }
        }

        // need a zero termination to identify the "last" label
        buffer.put( (uint8_t)0x00 );
        length += sizeof(uint8_t);

        return length;
    }

    /*!
      Reads a sequence of labels from a memory buffer

      This function is recursive in it's decompress. One of the things to be aware
      of are DNS packets that make circular offset references. Also, malformed packets
      that reference "bad" areas of the packet are no-no's

      \param domain Domain label to return
      \param buffer Memory buffer to read the domain from
      \throws std::out_of_range
    */
    void read_label(string& domain, dns_buffer_t & buffer)
    {
        while( true )
        {
            uint8_t   len;
          
            size_t thisPos = buffer.position();
            buffer.get(len);

            // 0xC0 denotes the offset
            if( len & 0xC0 )
            {
                uint8_t msb;
                buffer.get(msb);
                uint8_t lsb = len ^ 0xC0;
                uint16_t offset = lsb << 8 | msb;
            
                // bad dog! trying to reference the header
                if( offset < 0x0C )
                    throw std::out_of_range("Reference inside header"); // maybe we should throw a message?

                // bad dog! trying to reference ourselves!
                if( offset == thisPos )
                    throw std::out_of_range("Self Reference"); 

                // bad dog! trying to reference out-of-bounds!
                if( offset > buffer.length() )
                    throw std::out_of_range("Out of Bounds"); 

                // recurse the reference !
                size_t savedpos = buffer.position();

                buffer.position(offset); // make the jump to the reference

                read_label(domain, buffer);

                // safe to restore!
                if( savedpos < buffer.length() )
                    buffer.position(savedpos);

                // the compressed reference has the ending 0x00 byte marker
                break;
            }
            else if( len )
            {
                string s;
                buffer.get( s, len );

                domain += s + ".";
            }
            else
                break;
        }

        // we should always carry the "." in the name
        if( !domain.length() ) domain = ".";
    }
};

} // namespace net
} // namespace y

#include <boost/asio/detail/pop_options.hpp>

#endif  // BOOST_NET_RFC1035_414_HPP
