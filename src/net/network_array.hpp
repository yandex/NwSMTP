//
// network_array.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 1998-2006 Andreas Haberstroh (softwareace at yahoo dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_NET_NETWORK_ARRAY_HPP
#define BOOST_NET_NETWORK_ARRAY_HPP

// Our primary dependency is boost::asio. We can't live without it!
#include <boost/asio/detail/push_options.hpp>

#include <vector>
#include <string>

#include <boost/iterator.hpp>
#include <boost/cstdint.hpp>
#include <boost/scoped_array.hpp>
#include <boost/asio.hpp>
#include <boost/array.hpp>

using namespace std;
using namespace boost;
using namespace boost::asio;

namespace y {
namespace net {

/**
   The network_array class template provides a static size array of bytes 
   that has accessors function to make getting and setting data network friendly.

   Uses the Endian/Non-Endian transform functions, (i.e. htons,ntohs)

   Derived from boost::array.
*/
template<std::size_t N>
class network_array : public array<uint8_t, N>
{
  private:
    /// Position in memory buffer for get/put
    size_t  nap;  // acronym: network array position

    /// Total size of memory buffer, not necessarily the N size of the buffer
    size_t  nal; // acronym: network array length

  public:
    /// Constructs an empty network_array 
    /*

    */
    network_array() : nap(0), nal(0)
    {
        //    array<uint8_t,N>::assign((uint8_t)0x00);
    }

    /// Get & Set the position in the array
    /**
       @param p Sets the current caret position in the array. If left blank, it does not change the position, but only reports the position.
       @return The current caret position in the array
    */
    const size_t  position(const size_t p=N+1)
    {
        if( p != N + 1 )  nap = p;
        return nap; 
    }

    /// Get & Set the length of data in the array
    /**
       This function does not change the size of the array, but only the reporting aspect of the amount of data contained in the array.
       @param l Sets the data length in the array. If left blank, it does not change the length, but only reports the length.
       @return The current length of the array
    */
    const size_t  length(const size_t l=N+1)
    {
        if( l != N + 1 )  nal = l;
        return nal; 
    }    

    /// Gets data from the array
    /**
       Gets a char from the array.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(char & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        d = (char)array<uint8_t,N>::elems[nap];
        if( incpos ) nap += sizeof(d);

        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a char into the array.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const char d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        array<uint8_t,N>::elems[nap] = (uint8_t)d;
        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint8_t from the array.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(uint8_t & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        d = array<uint8_t,N>::elems[nap];

        if( incpos ) nap += sizeof(d);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint8_t into the array.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const uint8_t d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        array<uint8_t,N>::elems[nap] = d;

        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint16_t from the array. The data returned is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the  current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(uint16_t & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        d = ntohs( *((uint16_t *)&array<uint8_t,N>::elems[nap]) );

        if( incpos ) nap += sizeof(d);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint16_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the  current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const uint16_t d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        *((uint16_t *)&array<uint8_t,N>::elems[nap]) = htons(d);

        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint32_t from the array. The data is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(uint32_t & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        d = ntohl( *((uint32_t *)&array<uint8_t,N>::elems[nap]) );

        if( incpos ) nap += sizeof(d);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint32_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const uint32_t d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        *((uint32_t *)&array<uint8_t,N>::elems[nap]) = htonl(d);

        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint32_t from the array. The data is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(ip::address_v4 & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        d = ip::address_v4( ntohl( *((uint32_t *)&array<uint8_t,N>::elems[nap]) ) );

        if( incpos ) nap += sizeof(uint32_t);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint32_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const ip::address_v4 & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        *((uint32_t *)&array<uint8_t,N>::elems[nap]) = htonl(d.to_ulong());

        if( incpos )
        {
            nap += sizeof(uint32_t);
            if( nap > nal )
                nal += sizeof(uint32_t);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint32_t from the array. The data is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(ip::address_v6 & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        ip::address_v6::bytes_type  bytes;
        memcpy( &bytes.elems[0], &array<uint8_t,N>::elems[nap], 16);
        d = ip::address_v6(bytes);
        if( incpos )
        {
            nap += 16; 
            if( nap > nal ) nal += 16;
        }
        return 16;
    }

    /// Puts data into the array
    /**
       Puts a uint32_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const ip::address_v6 & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        memcpy( &array<uint8_t,N>::elems[nap], &d.to_bytes().elems[0], 16);

        if( incpos )
        {
            nap += sizeof(uint32_t);
            if( nap > nal )
                nal += sizeof(uint32_t);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a std::string from the array.
       @param d Data to retrieve
       @param len Amount of chars to read.
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(string & d, const size_t len, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        scoped_array<char> cPtr( new char[len + 1] );
        strncpy( cPtr.get(), (char*)&array<uint8_t,N>::elems[nap], len);
        cPtr.get()[len] = 0x00;
        d = cPtr.get();

        if( incpos )
        {
            nap += len;
            if( nap > nal )
                nal += len;
        }

        return len;
    }

    /// Puts data into the array
    /**
       Puts a std::string into the array.
       @param d Data to write into the array
       @param len Amount of chars to write
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const string & d, const size_t len, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 ) 
        {
            array<uint8_t,N>::rangecheck(p);
            position(p);
        }

        // make sure we can memcpy!
        array<uint8_t,N>::rangecheck(nap + len);
        memcpy( &array<uint8_t,N>::elems[nap], d.c_str(), len );

        if( incpos )
        {
            nap += len;
            if( nap > nal )
                nal += len;
        }

        return len;
    }
};

typedef network_array<576>        dns_buffer_t;
typedef shared_ptr<dns_buffer_t>  shared_dns_buffer_t;


} // namespace net
} // namespace y

#include <boost/asio/detail/pop_options.hpp>

#endif // BOOST_NET_NETWORK_ARRAY_HPP
