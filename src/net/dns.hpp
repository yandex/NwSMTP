//
// dns.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 1998-2008 Andreas Haberstroh (andreas at ibusy dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef BOOST_NET_DNS_HPP
#define BOOST_NET_DNS_HPP

#include <boost/asio/detail/push_options.hpp>

#include <vector>
#include <string>

#include <boost/asio.hpp>
#include <net/network_array.hpp>
#include <net/rfc1035_414.hpp>

using namespace std;
using namespace boost;
using namespace boost::algorithm;

namespace y {
namespace net {
namespace dns {

// quick forward declarations
class message;
class request_base_t;
class resource_base_t;

//! Shared Resource Base Pointer
typedef shared_ptr<resource_base_t>         shared_resource_base_t;

//! A list of resource records
typedef std::vector<shared_resource_base_t> rr_list_t;

//! A shared list of resource records
typedef shared_ptr<rr_list_t>               shared_rr_list_t;

//! Shared Request Base Pointer
typedef shared_ptr<request_base_t>          shared_request_base_t;

//! Class identification for resource records. Included is the QCLASS that is in the 0xF0 range.
typedef enum
{
    class_none = 0x00,  //!< No class definition
    class_in,           //!< Internet class. Default class
    class_cs,           //!< CSNET class, obsolete, used for examples.
    class_ch,           //!< CHAOS class
    class_hs,           //!< Hesiod [Dyer 87]
    class_all = 0xff    //!< Query all classes
} class_t;

//! Type identification for resource records. Included are the QTYPE's that are in the 0xF0 range
typedef enum
{
    type_none  = 0x00,  //!< No type definition.
    type_a     = 0x01,  //!< Address type
    type_ns    = 0x02,  //!< Name Server type
    type_cname = 0x05,  //!< Canonical name type
    type_soa   = 0x06,  //!< Start of Authority type
    type_ptr   = 0x0c,  //!< Pointer type
    type_hinfo = 0x0d,  //!< Host Information type
    type_mx    = 0x0f,  //!< Mail Exchanger type
    type_txt   = 0x10,  //!< Text type
    type_a6    = 0x1c,  //!< Address (IP6) type
    type_srv   = 0x21,  //!< Service type
    type_axfr  = 0xfc,  //!< Zone transfer type
    //  type_all   = 0xff   //!< Query all types
} type_t;

/*!
  Basic definition of a DNS request.

  Shared by Questions and all the different resource record types
*/
class request_base_t
{
  protected:
    /// Domain name of the resource record
    string    rr_domain;

    /// Resource record type
    uint16_t  rr_type;

    /// Resource record class
    uint16_t  rr_class;

  public:
    /// Default constructor
    request_base_t()
            : rr_type(type_none), rr_class(class_none)
    {}

    /*!
      Copy contructor

      \param o request_base_t to copy
    */
    request_base_t(const request_base_t & o)
            : rr_domain(o.rr_domain), rr_type(o.rr_type), rr_class(o.rr_class)
    {
    }

    /*!
      Constructs a request_base_t

      \param t Resource type to create object for
      \param c Resource class to create object for
    */
    request_base_t(const type_t t, const class_t c=class_in)
            : rr_type(t), rr_class(c)
    {
    }

    /*!
      Constructs a request_base_t

      \param d Domain name to create object for
      \param t Resource type to create object for
      \param c Resource class to create object for
    */
    request_base_t(const string & d, const type_t t, const class_t c=class_in)
            : rr_domain(d), rr_type(t), rr_class(c)
    {}

    /*!
      Constructor that creates the request_base_t from a network buffer

      \param buffer Memory buffer to read from
      \param offset_map DNS label compression map for label/offset values
    */
    request_base_t(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        decode(buffer, offset_map);
    }

    /// Virtual Destructor
    virtual ~request_base_t()
    {
    }

    /*!
      Sets the domain name

      \param s Domain name to assign to the request_base_t
      \return current domain name
    */
    const string& domain(const string& s)
    {
        return domain(s.c_str());
    }

    /*!
      Sets the domain name

      \param s Domain name to assign to the request_base_t.
      \return current domain name
    */
    const string& domain(const char* s)
    {
        rr_domain = s;
        return rr_domain;
    }

    /*!
      Gets the domain name

      \return current domain name
    */
    const string& domain() const
    {
        return rr_domain;
    }


    /*!
      Sets the resource record type

      \param t resource type to assign to the request_base_t.
      \return Current type
    */
    const type_t  rtype(const type_t t)
    {
        rr_type = t;
        return (type_t)rr_type;
    }

    /*!
      Gets the resource record type

      \return Current type
    */
    const type_t  rtype() const
    {
        return (type_t)rr_type;
    }

    /*!
      Sets the resource record class

      \param c resource class to assign to the request_base_t.
      \return current class
    */
    const class_t  rclass(const class_t c)
    {
        rr_class = c;
        return (class_t)rr_class;
    }

    /*!
      Gets the resource record class

      \return current class
    */
    const class_t  rclass() const
    {
        return (class_t)rr_class;
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /*!
      Encodes the request_base_t into a memory buffer

      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        offset_map.write_label(rr_domain, buffer);
        BOOST_ASSERT( rr_type != 0x0000 );
        buffer.put( rr_type );
        BOOST_ASSERT( rr_class != 0x0000 );
        buffer.put( rr_class );
    }

    /*!
      Decodes the request_base_t into a memory buffer

      \param buffer Buffer to decode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        offset_map.read_label(rr_domain, buffer);
        buffer.get( rr_type );
        buffer.get( rr_class );
    }
};

/// A question is a simple thing
class question : public request_base_t
{
  public:
    /// Default constructor
    question()
            : request_base_t()
    {}

    /*!
      Copy contructor

      \param o question to copy
    */
    question(const request_base_t & o)
            : request_base_t(o)
    {
    }

    /*!
      Copy contructor

      \param o question to copy
    */
    question(const question & o)
            : request_base_t()
    {
        domain(o.domain());
        rtype(o.rtype());
        rclass(o.rclass());
    }

    /*!
      Constructs a question

      \param t Resource type to create object for
      \param c Resource class to create object for
    */
    question(const type_t t, const class_t c=class_in)
            : request_base_t(t, c)
    {
    }

    /*!
      Constructs a question

      \param d Domain name to create object for
      \param t Resource type to create object for
      \param c Resource class to create object for
    */
    question(const string & d, const type_t t, const class_t c=class_in)
            : request_base_t(d, t, c)
    {}

    /*!
      Constructor that creates the question from a network buffer

      \param buffer Memory buffer to read from
      \param offset_map DNS label compression map for label/offset values
    */
    question(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
            : request_base_t(buffer, offset_map)
    {
    }

    /// Virtual Destructor
    virtual ~question()
    {
    }
};

/*!
  Basic definition of a DNS resource record.

*/
class   resource_base_t : public request_base_t
{
  private:
    /// Time To Live value for the resource record
    uint32_t  rr_ttl;

    /// Resource Record payload length
    uint16_t  rr_length;

  public:
    /// Constructs an empty resource_base_t
    resource_base_t()
            : request_base_t(), rr_ttl(0), rr_length(0)
    {}

    /*!
      Copy contructor

      \param o resource_base_t to copy
    */
    resource_base_t(const resource_base_t& o)
            : request_base_t(o), rr_ttl(o.rr_ttl), rr_length(o.rr_length)
    {}

    /*!
      Sets the resource type and defaults the resource class to class_in.

      \param t Resource type to create object for
    */
    resource_base_t(const type_t t)
            : request_base_t(t,class_in), rr_ttl(0), rr_length(0)
    {}

    /*!
      Defaults the resource class to class_in.

      \param s Domain name to create object for
      \param t Resource type to create object for
    */
    resource_base_t(const string& s, const type_t t)
            : request_base_t(s,t,class_in), rr_ttl(0), rr_length(0)
    {}

    /*!
      Constructor that creates the resource_base_t from a memory buffer

      \param buffer Memory buffer to read from
      \param offset_map
    */
    resource_base_t(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        decode(buffer, offset_map);
    }

    virtual ~resource_base_t()
    {
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new resource_base_t(*this));
    }

    /*!
      Sets the Time To Live value

      \param t Time to Live to assign to the resource_base_t.
      \return TTL value
    */
    const uint32_t  ttl(const uint32_t t)
    {
        rr_ttl = t;
        return rr_ttl;
    }

    /*!
      Gets the Time To Live value

      \return TTL value
    */
    const uint32_t ttl() const
    {
        return rr_ttl;
    }

    /*!
      Sets the payload length of the resource record

      \param t Payload length to assign to the resource_base_t.
      \return payload length
    */
    const uint16_t  length(const uint16_t t)
    {
        rr_length = t;
        return rr_length;
    }

    /*!
      Gets the payload length of the resource record

      \return payload length
    */
    const uint16_t  length() const
    {
        return rr_length;
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /*!
      Encodes the resource_base_t into a memory buffer

      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        request_base_t::encode(buffer, offset_map);
        buffer.put( rr_ttl );
        buffer.put( rr_length );
    }

    /*!
      Decodes the resource_base_t from a memory buffer

      \param buffer Buffer to decode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        request_base_t::decode(buffer, offset_map);
        buffer.get( rr_ttl );
        buffer.get( rr_length );
    }
};

/*!
  Definition for an unknown resource

  The RFC states that DNS cache servers should handle unknown RR types and simply pass them on as requested.
  For instance, the original RFC didn't specify SRV records. And, many servers couldn't handle those types.
  So, this class has an "unknown" type and simply passes unknown RRR types along as needed.
*/
class unknown_resource : public resource_base_t
{
  protected:
    /// Raw data for the unknown resource records.
    shared_ptr<uint8_t> _data;

  public:
    /// Default contructor
    unknown_resource() : resource_base_t() {;}

    /*!
      Copy Constructor

      \param o unknown resource to copy from
    */
    unknown_resource(const unknown_resource& o)
            : resource_base_t(o)
    {
        _data = shared_ptr<uint8_t>( new uint8_t[length()] );
        memcpy( _data.get(), o._data.get(), length() );
    }

    /*!
      Copy Constructor

      \param o resource_base_t to copy from
    */
    unknown_resource(const resource_base_t& o) : resource_base_t(o) { ; }

    /// Virtual Destructor
    virtual ~unknown_resource()
    {
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new unknown_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /*!
      Encodes the a resource into a memory buffer

      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        for( size_t i = 0; i < length(); ++i )
            buffer.put( _data.get()[i] );
    }

    /*!
      Decodes the a resource into a memory buffer

      \param buffer Buffer to decode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        _data = shared_ptr<uint8_t>( new uint8_t[length()] );
        for( size_t i = 0; i < length(); ++i )
            buffer.get( _data.get()[i] );
    }
};

/*!
  Definition for an A resource record
*/
class a_resource : public resource_base_t
{
  protected:
    /// IP 4 address
    ip::address_v4 rr_address;

  public:
    /// Default contructor
    a_resource() : resource_base_t(type_a), rr_address(0)  {;}

    /*!
      Constructs a a_resource

      \param s Host name for the A record
    */
    a_resource(const string& s) : resource_base_t(s, type_a), rr_address(0)  {;}

    /// Virtual Destructor
    virtual ~a_resource()
    {
    }

    /*!
      Sets the IP4 address from a ip::address_v4

      \param addr Address to assign to the a_resource.
      \return Address
    */
    const ip::address_v4& address(const ip::address_v4& addr)
    {
        rr_address = addr;
        return rr_address;
    }

    /*!
      Sets the IP4 address from a dotted decimal string

      \param s Address to assign to the a_resource.
      \return Address
    */
    const ip::address_v4& address(const char* s)
    {
        return address(ip::address_v4::from_string(s));
    }

    /*!
      Gets the IP4 address

      \return Address
    */
    const ip::address_v4& address() const
    {
        return rr_address;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new a_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /*!
      Copy Constructor

      \param o a_resource to copy from
    */
    a_resource(const a_resource& o) : resource_base_t(o), rr_address(o.rr_address) { ; }

    /*!
      Copy Constructor

      \param o resource_base_t to copy from
    */
    a_resource(const resource_base_t& o) : resource_base_t(o), rr_address(0)  { ; }


    /*!
      Encodes the a resource into a memory buffer

      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        // the length offset for the resource record
        size_t lenOffset( buffer.position() - sizeof(uint16_t) );

        size_t len(0);

        len = buffer.put( rr_address );

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /*
      Decodes the a resource into a memory buffer

      \param buffer Buffer to decode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        buffer.get(rr_address);
    }
};

/*!
  Definition for an NS resource record

*/
class ns_resource : public resource_base_t
{
  protected:
    /// name server name
    string      rr_nsdname;

  public:
    /// Default contructor
    ns_resource() : resource_base_t(type_ns) {;}

    /*!
      Constructs a ns_resource from a string

      \param s Host name for the NS record
    */
    ns_resource(const string& s) : resource_base_t(s, type_ns) {;}

    /// Virtual Destructor
    virtual ~ns_resource()
    {
    }

    /*!
      Sets the nameserver from a string

      \param s Nameserver to assign to the ns_resource.
      \return Nameserver
    */
    const string& nameserver(const string& s)
    {
        return nameserver(s.c_str());
    }

    /*!
      Sets the nameserver from a null-terminated C tring

      \param s Nameserver string to assign to the ns_resource.
      \return Nameserver
    */
    const string& nameserver(const char* s)
    {
        rr_nsdname = s;
        return rr_nsdname;
    }

    /*!
      Sets the nameserver

      \return Nameserver
    */
    const string& nameserver() const
    {
        return rr_nsdname;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new ns_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /*!
      Copy Constructor

      \param o ns_resource to copy from
    */
    ns_resource(const ns_resource& o) : resource_base_t(o), rr_nsdname(o.rr_nsdname) { ; }

    /*!
      Copy Constructor

      \param o resource_base_t to copy from
    */
    ns_resource(const resource_base_t& o)
            : resource_base_t(o)
    {
    }

    /*!
      Encodes the ns resource into a memory buffer

      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len = offset_map.write_label(rr_nsdname, buffer);

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /*!
      Decodes the ns resource into a memory buffer

      \param buffer Buffer to decode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        offset_map.read_label(rr_nsdname, buffer);
    }
};

/*!
  Definition of a CNAME resource
*/
class cname_resource : public resource_base_t
{
  protected:
    /// Canonical Name
    string  rr_cname;

  public:
    /// Default contructor
    cname_resource() : resource_base_t(type_cname) {;}

    /*!
      Constructs a cname_resource

      \param s Host name for the CNAME record
    */
    cname_resource(const string& s) : resource_base_t(s, type_cname) {;}

    /// Virtual Destructor
    virtual ~cname_resource()
    {
    }

    /*!
      Sets the Canonical name

      \param s Canonical name to assign to the cname_resource.
      \return Canonical Name
    */
    const string& canonicalname(const string& s)
    {
        return canonicalname(s.c_str());
    }

    /*!
      Sets the Canonical name

      \param s Canonical name string to assign to the cname_resource.
      \return Canonical name
    */
    const string& canonicalname(const char* s)
    {
        rr_cname = s;
        return rr_cname;
    }

    /*!
      Gets the Canonical name

      \return Canonical name
    */
    const string& canonicalname() const
    {
        return rr_cname;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new cname_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /*!
      Copy Constructor

      \param o cname_resource to copy from
    */
    cname_resource(const cname_resource& o) : resource_base_t(o), rr_cname(o.rr_cname) { ; }

    /*!
      Copy Constructor

      \param o resource_base_t to copy from
    */
    cname_resource(const resource_base_t& o) : resource_base_t(o) { ; }

    /*!
      Encodes the cname resource into a memory buffer

      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len = offset_map.write_label(rr_cname, buffer);

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /*!
      Decodes the cname resource into a memory buffer

      \param buffer Buffer to decode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        offset_map.read_label(rr_cname, buffer);
    }
};

/*!
  Definition of a SOA resource
*/
class soa_resource : public resource_base_t
{
  protected:
    /// Master Name
    string        rr_mname;
    /// Responsible Name
    string        rr_rname;
    /// Serial Number for SOA record
    uint32_t  rr_serial;
    /// Refresh Time
    uint32_t  rr_refresh;
    /// Retry Time
    uint32_t  rr_retry;
    /// Exipiration Time
    uint32_t  rr_expire;
    /// Minimum TTL
    uint32_t  rr_minttl;

  public:
    /// Default contructor
    soa_resource() : resource_base_t(type_soa), rr_serial(0), rr_refresh(0), rr_retry(0), rr_expire(0), rr_minttl(0) {;}

    /*!
      Constructs a soa_resource

      \param s Host name for the SOA record
    */
    soa_resource(const string& s) : resource_base_t(s, type_soa), rr_serial(0), rr_refresh(0), rr_retry(0), rr_expire(0), rr_minttl(0) {;}

    /// Virtual Destructor
    virtual ~soa_resource()
    {
    }

    /*!
      Sets the Master Name

      \param s Master Name to assign to the soa_resource.
      \return Master Name
    */
    const string& master_name(const string& s)
    {
        return master_name(s.c_str());
    }

    /*!
      Sets the Master Name

      \param s Master Name string to assign to the soa_resource.
      \return Master Name
    */
    const string& master_name(const char* s)
    {
        rr_mname = s;
        return rr_mname;
    }

    /*!
      Gets the Master Name

      \return Master Name
    */
    const string& master_name() const
    {
        return rr_mname;
    }

    /*!
      Sets the Responsible Name

      \param s Responsible Name to assign to the soa_resource.
      \return Responsible Name
    */
    const string& responsible_name(const string& s)
    {
        return responsible_name(s.c_str());
    }

    /*!
      Sets the Responsible Name

      \param s Responsible Name to assign to the soa_resource.
      \return Responsible Name
    */
    const string& responsible_name(const char* s)
    {
        rr_rname = s;
        return rr_rname;
    }

    /*!
      Gets the Responsible Name

      \return Responsible Name
    */
    const string& responsible_name() const
    {
        return rr_rname;
    }

    /*!
      Sets the Serial number

      \param d Serial number to assign to the soa_resouce.
      \return Serial number
    */
    const uint32_t serial_number(const uint32_t d)
    {
        rr_serial = d;
        return rr_serial;
    }

    /*!
      Gets the Serial number

      \return Serial number
    */
    const uint32_t serial_number() const
    {
        return rr_serial;
    }

    /*!
      Sets the refresh time

      \param d Refresh time to assign to the soa_resouce.
      \return Refresh time
    */
    const uint32_t refresh(const uint32_t d)
    {
        rr_refresh = d;
        return rr_refresh;
    }

    /*!
      Gets the refresh time

      \return Refresh time
    */
    const uint32_t refresh() const
    {
        return rr_refresh;
    }

    /*!
      Sets the Retry time

      \param d Retry time to assign to the soa_resouce.
      \return Retry time
    */
    const uint32_t retry(const uint32_t d)
    {
        rr_retry = d;
        return rr_retry;
    }

    /*!
      Gets the Retry time

      \return Retry time
    */
    const uint32_t retry() const
    {
        return rr_retry;
    }

    /*!
      Sets the Exipiration time

      \param d Exipiration time to assign to the soa_resouce.
      \return Exipiration time
    */
    const uint32_t expire(const uint32_t d)
    {
        rr_expire = d;
        return rr_expire;
    }

    /*!
      Gets the Exipiration time

      \return Exipiration time
    */
    const uint32_t expire() const
    {
        return rr_expire;
    }

    /*!
      Sets the Minimum TTL

      \param d Minimum TTL to assign to the soa_resouce.
      \return Minimum TTL
    */
    const uint32_t minttl(const uint32_t d)
    {
        rr_minttl = d;
        return rr_minttl;
    }

    /*!
      Gets the Minimum TTL

      \return Minimum TTL
    */
    const uint32_t minttl() const
    {
        return rr_minttl;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new soa_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /*!
      Copy Constructor

      \param o soa_resource to copy from
    */
    soa_resource(const soa_resource& o)
            : resource_base_t(o)
    {
        rr_mname = o.rr_mname;
        rr_rname = o.rr_rname;
        rr_serial = o.rr_serial;
        rr_refresh = o.rr_refresh;
        rr_retry = o.rr_retry;
        rr_expire = o.rr_expire;
        rr_minttl = o.rr_minttl;
    }

    /*!
      Copy Constructor

      \param o resource_base_t to copy from
    */
    soa_resource(const resource_base_t& o) : resource_base_t(o), rr_serial(0), rr_refresh(0), rr_retry(0), rr_expire(0), rr_minttl(0) {;}

    /*!
      Encodes the soa resource into a memory buffer

      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len(0);

        len += offset_map.write_label(rr_mname, buffer);
        len += offset_map.write_label(rr_rname, buffer);
        len += buffer.put( rr_serial );
        len += buffer.put( rr_refresh );
        len += buffer.put( rr_retry );
        len += buffer.put( rr_expire );
        len += buffer.put( rr_minttl );

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /*!
      Decodes the soa_resource into a memory buffer

      \param buffer Buffer to decode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        offset_map.read_label(rr_mname, buffer);
        offset_map.read_label(rr_rname, buffer);

        buffer.get( rr_serial );
        buffer.get( rr_refresh );
        buffer.get( rr_retry );
        buffer.get( rr_expire );
        buffer.get( rr_minttl );
    }

};

/*!
  Definition of a PTR resource
*/
class ptr_resource : public resource_base_t
{
  protected:
    /// Pointer name
    string rr_ptrdname;

  public:
    /// Default contructor
    ptr_resource() : resource_base_t(type_ptr) {;}

    /// Constructs a ptr_resource
    /*
      \param s Host name for the PTR record
    */
    ptr_resource(const string& s) : resource_base_t(s, type_ptr) {;}

    /// Virtual Destructor
    virtual ~ptr_resource()
    {
    }

    /// Pointer set function
    /*
      \param t Pointer to assign to the ptr_resource.
      \return Pointer
    */
    const string& pointer(const string& s)
    {
        return pointer(s.c_str());
    }

    /// Pointer get/set function
    /*
      \param t Pointer string to assign to the ptr_resource. If left blank, will return the
      current pointer only.
      \return Pointer
    */
    const string& pointer(const char* s=0)
    {
        if( s ) rr_ptrdname = s;
        return rr_ptrdname;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new ptr_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /// Copy Constructor
    /*
      \param o ptr_resource to copy from
    */
    ptr_resource(const ptr_resource& o) : resource_base_t(o), rr_ptrdname(o.rr_ptrdname) { ; }

    /// Copy Constructor
    /*
      \param o resource_base_t to copy from
    */
    ptr_resource(const resource_base_t& o) : resource_base_t(o) { ; }

    /// Encodes the ptr resource into a memory buffer
    /*
      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len = offset_map.write_label(rr_ptrdname, buffer);

        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /// Decodes the ptr resource into a memory buffer
    /*
      \param buffer Buffer to decode the request into
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        offset_map.read_label(rr_ptrdname, buffer);
    }
};

/// Definition of a HINFO resource
/**
 */
class hinfo_resource : public resource_base_t
{
  protected:
    /// CPU description
    string      rr_cpu;
    /// OS description
    string      rr_os;

  public:
    /// Default contructor
    hinfo_resource() : resource_base_t(type_hinfo) {;}

    /// Constructs a hinfo_resource
    /*
      \param s Host name for the PTR record
    */
    hinfo_resource(const string& s) : resource_base_t(s, type_hinfo) {;}

    /// Virtual Destructor
    virtual ~hinfo_resource()
    {
    }

    /// CPU description set function
    /*
      \param t CPU description to assign to the hinfo_resource.
      \return CPU description
    */
    const string& cpu(const string& s)
    {
        return cpu(s.c_str());
    }

    /// CPU description get/set function
    /*
      \param t CPU description string to assign to the hinfo_resource. If left blank, will return the
      current CPU description only.
      \return CPU description
    */
    const string& cpu(const char* s=0)
    {
        if( s ) rr_cpu = s;
        return rr_cpu;
    }

    /// OS description set function
    /*
      \param t OS description to assign to the hinfo_resource.
      \return OS description
    */
    const string& os(const string& s)
    {
        return os(s.c_str());
    }

    /// OS description get/set function
    /*
      \param t OS description string to assign to the hinfo_resource. If left blank, will return the
      current OS description only.
      \return OS description
    */
    const string& os(const char* s=0)
    {
        if( s ) rr_os = s;
        return rr_os;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new hinfo_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /// Copy Constructor
    /*
      \param o hinfo_resource to copy from
    */
    hinfo_resource(const hinfo_resource& o) : resource_base_t(o), rr_cpu(o.rr_cpu), rr_os(o.rr_os) { ; }

    /// Copy Constructor
    /*
      \param o resource_base_t to copy from
    */
    hinfo_resource(const resource_base_t& o) : resource_base_t(o) { ; }


    /// Encodes the hinfo resource into a memory buffer
    /*
      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len(0);

        len += buffer.put( (uint8_t)rr_cpu.length() );
        len += buffer.put( rr_cpu, rr_cpu.length() );
        len += buffer.put( (uint8_t)rr_os.length() );
        len += buffer.put( rr_os, rr_os.length() );

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /// Decodes the hinfo resource into a memory buffer
    /*
      \param buffer Buffer to decode the request into
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        uint16_t len(0);

        buffer.get(len);
        buffer.get(rr_cpu, len);

        buffer.get(len);
        buffer.get(rr_os, len);
    }
};

/// Definition of a MX resource
/*
 */
class mx_resource : public resource_base_t
{
  protected:
    /// Preference value
    uint16_t  rr_preference;
    /// Mail Exchange(server)
    string    rr_exchange;

  public:
    /// Default contructor
    mx_resource() : resource_base_t(type_mx), rr_preference(0) {}

    /// Constructs a mx_resource
    /*
      \param s Host name for the MX record
    */
    mx_resource(const string& s) : resource_base_t(s, type_mx), rr_preference(0) {}

    /// Virtual Destructor
    virtual ~mx_resource()
    {
    }

    /// Mail exchange(server) set function
    /*
      \param t Mail exchange(server) to assign to the mx_resource.
      \return Mail exchange(server)
    */
    const string& exchange(const string& s)
    {
        return exchange(s.c_str());

    }

    /// Mail Exchange(server) get/set function
    /*
      \param t Mail exchange(server) string to assign to the mx_resource. If left blank, will return the
      current mail exchange(server) only.
      \return Mail exchange(server)
    */
    const string& exchange(const char* s=0)
    {
        if( s ) rr_exchange = s;
        return rr_exchange;
    }

    /// Preference value get/set function
    /*
      \param t Preference value to assign to the mx_resource. If left blank, will return the
      current preference value only.
      \return Preference value
    */
    const uint16_t preference(const uint16_t d = 0xffff)
    {
        if( d != 0xffff ) rr_preference = d;
        return rr_preference;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new mx_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /// Copy Constructor
    /*
      \param o mx_resource to copy from
    */
    mx_resource(const mx_resource& o) : resource_base_t(o), rr_preference(o.rr_preference), rr_exchange(o.rr_exchange) { ; }

    /// Copy Constructor
    /*
      \param o resource_base_t to copy from
    */
    mx_resource(const resource_base_t& o) : resource_base_t(o), rr_preference(0) {}


    /// Encodes the mx resource into a memory buffer
    /*
      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len(0);

        len += buffer.put( rr_preference );
        len += offset_map.write_label(rr_exchange, buffer);

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /// Decodes the mx resource into a memory buffer
    /*
      \param buffer Buffer to decode the request into
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        buffer.get( rr_preference );
        offset_map.read_label(rr_exchange, buffer);
    }

};

/// Definition of a TXT resource
/**
 */
class txt_resource : public resource_base_t
{
  protected:
    /// Text string
    string      rr_text;

  public:
    /// Default contructor
    txt_resource() : resource_base_t(type_txt) {;}

    /// Constructs a txt_resource
    /*
      \param s Host name for the TXT record
    */
    txt_resource(const string& s) : resource_base_t(s, type_txt) {;}

    /// Virtual Destructor
    virtual ~txt_resource()
    {
    }

    /// Text string set function
    /*
      \param t Text string to assign to the txt_resource.
      \return Text string
    */
    const string& text(const string& s)
    {
        return text(s.c_str());
    }

    /// Text string get/set function
    /*
      \param t Text string to assign to the txt_resource. If left blank, will return the
      current text string only.
      \return Text string
    */
    const string& text(const char* s=0)
    {
        if( s ) rr_text = s;
        return rr_text;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new txt_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /// Copy Constructor
    /*
      \param o txt_resource to copy from
    */
    txt_resource(const txt_resource& o) : resource_base_t(o), rr_text(o.rr_text) { ; }

    /// Copy Constructor
    /*
      \param o resource_base_t to copy from
    */
    txt_resource(const resource_base_t& o) : resource_base_t(o) { ; }

    /// Encodes the txt resource into a memory buffer
    /*
      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len(0);

        len += buffer.put( (uint8_t)rr_text.length() );
        len += buffer.put( rr_text, rr_text.length() );

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /// Decodes the txt resource into a memory buffer
    /*
      \param buffer Buffer to decode the request into
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        uint8_t  len;
        int savedpos = buffer.position();
        int rr_len = length();
        rr_text.reserve(rr_len);
        buffer.get(len);
        buffer.get(rr_text, len);
        int i = rr_len - len - 1;
        while (i > 0)
        {
            string d;
            buffer.get(len);
            buffer.get(d, len);
            rr_text += d;
            i -= (len+1);
        }
        buffer.position(savedpos + rr_len);
    }

};

/// Definition for an A6 resource record
/*
 */
class a6_resource : public resource_base_t
{
  protected:
    /// IP 6 address
    ip::address_v6 rr_address;

  public:
    /// Default contructor
    a6_resource() : resource_base_t(type_a6) {;}

    /// Constructs a a6_resource
    /*
      \param s Host name for the A record
    */
    a6_resource(const string& s) : resource_base_t(s, type_a6) {;}

    /// Virtual Destructor
    virtual ~a6_resource()
    {
    }

    /// Address set function
    /*
      \param t Address to assign to the a6_resource.
      \return Address
    */
    const ip::address_v6& address(const ip::address_v6& addr)
    {
        rr_address = addr;
        return rr_address;
    }

    /// Address get/set function
    /*
      \param t Dotted decimal address string to assign to the a6_resource. If left blank, will return the
      current address only.
      \return Address
    */
    const ip::address_v6& address(const char* s=0)
    {
        if( s != 0 )  return address(ip::address_v6::from_string(s));
        return rr_address;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new a6_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /// Copy Constructor
    /*
      \param o a6_resource to copy from
    */
    a6_resource(const a6_resource& o) : resource_base_t(o), rr_address(o.rr_address) { ; }

    /// Copy Constructor
    /*
      \param o resource_base_t to copy from
    */
    a6_resource(const resource_base_t& o) : resource_base_t(o) { ; }

    /// Encodes the a resource into a memory buffer
    /*
      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        // the length offset for the resource record
        size_t lenOffset( buffer.position() - sizeof(uint16_t) );

        size_t len(0);

        len = buffer.put( rr_address );

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /// Decodes the a resource into a memory buffer
    /*
      \param buffer Buffer to decode the request into
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        buffer.get(rr_address);
    }
};

/// Definition of a SRV resource
/*
 */
class srv_resource : public resource_base_t
{
  protected:
    uint16_t  rr_priority;  //!< Priority of the target host
    uint16_t  rr_weight;    //!< Weight of the record, used as a selection method
    uint16_t  rr_port;      //!< Port for the target host's service
    string    rr_target;    //!< Target name of the host

  public:
    /// Default contructor
    srv_resource() : resource_base_t(type_srv)  { ; }

    /// Constructs a srv_resource
    /*
      \param s Host name for the TXT record
    */
    srv_resource(const string& s) : resource_base_t(s, type_srv) {;}

    /// Virtual Destructor
    virtual ~srv_resource()
    {
    }

    /// Priority value get/set function
    /*
      \param t Priority value to assign to the srv_resource. If left blank, will return the current priority value only.
      \return Priority value
    */
    const uint16_t priority(const uint16_t d = 0xffff)
    {
        if( d != 0xffff ) rr_priority = d;
        return rr_priority;
    }

    /// Weight value get/set function
    /*
      \param t Weight value to assign to the srv_resource. If left blank, will return the current weight value only.
      \return Weight value
    */
    const uint16_t weight(const uint16_t d = 0xffff)
    {
        if( d != 0xffff ) rr_weight = d;
        return rr_weight;
    }

    /// Port value get/set function
    /*
      \param t Port value to assign to the srv_resource. If left blank, will return the current port value only.
      \return Port value
    */
    const uint16_t port(const uint16_t d = 0xffff)
    {
        if( d != 0xffff ) rr_port = d;
        return rr_port;
    }

    /// Target host set function
    /*
      \param t Target host string to assign to the srv_resource.
      \return Target host string
    */
    const string& targethost(const string& s)
    {
        return targethost(s.c_str());

    }

    /// Target host  get/set function
    /*
      \param t Target host  name to assign to the srv_resource. If left blank, will return the current target host string only.
      \return Target host string
    */
    const string& targethost(const char* s=0)
    {
        if( s ) rr_target = s;
        return rr_target;
    }

    /*!
      Clones an existing resource record object
    */
    virtual shared_resource_base_t clone() const
    {
        return shared_resource_base_t(new srv_resource(*this));
    }

    /// Friend to tie to the containers in the message class.
    friend class message;

  protected:
    /// Copy Constructor
    /*
      \param o srv_resource to copy from
    */
    srv_resource(const srv_resource& o)
            : resource_base_t(o), rr_priority(o.rr_priority), rr_weight(o.rr_weight), rr_port(o.rr_port), rr_target(o.rr_target) { ; }

    /// Copy Constructor
    /*
      \param o resource_base_t to copy from
    */
    srv_resource(const resource_base_t& o) : resource_base_t(o) { ; }


    /// Encodes the srv resource into a memory buffer
    /*
      \param buffer Buffer to encode the request into
      \param offset_map DNS label compression map for label/offset values
    */
    virtual void encode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        resource_base_t::encode(buffer, offset_map);

        size_t lenOffset( buffer.position() - sizeof(uint16_t) );
        size_t len(0);

        len += buffer.put(rr_priority);
        len += buffer.put(rr_weight);
        len += buffer.put(rr_port);
        len += offset_map.write_label(rr_target, buffer);

        // lastly, update the length field
        buffer.put( (uint16_t)len, lenOffset, false );
    }

    /// Decodes the srv resource into a memory buffer
    /*
      \param buffer Buffer to decode the request into
    */
    virtual void decode(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        buffer.get(rr_priority);
        buffer.get(rr_weight);
        buffer.get(rr_port);
        offset_map.read_label(rr_target, buffer);
    }

};

/// DNS Request/Response Message
/**
 */
class message
{
  private:
    /// Bit fields for the header
    typedef     struct  bit_fields_header
    {
        /// Defines the action of the message, query/response
        uint16_t        Action:1,
            /// Operation code of the message
            OpCode:4,
            /// Defines if the message is from an authority
            Authority:1,
            /// Defines if the message was truncated due to size limitation of the transmission channel
            Truncated:1,
            /// Defines if name server being queried should recursively find an answer.
            RD:1,
            /// Defines if the names server supports recursive queries
            RA:1,
            /// Reserved bits
            Z:3,
            /// Response code for the query
            RCODE:4;
    } bit_fields_header;

    /// Header bytes of the message
    typedef struct opaque_header
    {
        /// Message id
        uint16_t        Id;
        /// Bitfields as defined in the bit_fields_header structure
        uint16_t        bit_fields;
        /// Question count
        uint16_t        QdCount;
        /// Resource record answer count
        uint16_t        AnCount;
        /// Name server count
        uint16_t        NsCount;
        /// Additional resource records
        uint16_t        ArCount;
    } opaque_header;

  public:
    /// Used by the action field of the header
    typedef     enum
    {
        /// No action to take.
        no_action = -1,
        /// Query the name server
        query = 0,
        /// Response from the name server
        response
    } action_t;

    /// Specifies the type of request operation.
    typedef     enum
    {
        /// No operation to take
        no_opcode = -1,
        /// Standard query
        squery = 0,
        /// Inverse query
        iquery,
        /// Server status query
        status
    } opcode_t;

    /// Response codes from a request operation
    typedef enum
    {
        /// No error
        noerror = 0,
        /// Message is malformed
        format_error,
        /// Server had an internal error
        server_error,
        /// The domain name does not exist on the name server being queried
        name_error,
        /// Name server does not support the query
        not_implemented,
        /// Name server refused the request
        refused,
        /// No result
        no_result
    } result_t;

    /// A list of questions
    typedef std::vector<question>               questions_t;

  private:
    /// Header bytes of the message
    opaque_header header;

    /// Question list
    questions_t question_section;
    /// Answer list
    rr_list_t   answer_section;
    /// Authoritative records list
    rr_list_t   authority_section;
    /// Additional records list
    rr_list_t   additional_section;

  public:
    /// Default constructor
    message()
    {
        memset(&header, 0x00, sizeof(header));
    }

    /*!
      Constructs a query message with a default question

      \param q question to ask
    */
    message( const dns::question& q)
    {
        memset(&header, 0x00, sizeof(header));
        question_section.push_back( q );

        recursive(true);
        action(dns::message::query);
        opcode(dns::message::squery);
    }

    /*!
      Constructs a query message with a default question

      \param d Domain to query
      \param t Resource type to query
    */
    message(const string & d, const type_t t)
    {
        memset(&header, 0x00, sizeof(header));
        question_section.push_back( dns::question(d, t) );

        recursive(true);
        action(dns::message::query);
        opcode(dns::message::squery);
    }

    /*!
      Copy constructor

      \param p message to copy from
    */
    message(const message& p)
    {
        operator=(p);
    }

    /*!
      Assignment operator

      \param p message to assign from
    */
    const message& operator=(const message& p)
    {
        memcpy(&header, &p.header, sizeof(header));

        rr_list_t::const_iterator   rIter;
        questions_t::const_iterator qIter;

        question_section.clear();
        for( qIter = p.question_section.begin(); qIter != p.question_section.end(); ++qIter)
            question_section.push_back( (*qIter) );

        answer_section.clear();
        for( rIter = p.answer_section.begin(); rIter != p.answer_section.end(); ++rIter)
            answer_section.push_back( (*rIter) );

        authority_section.clear();
        for( rIter = p.authority_section.begin(); rIter != p.authority_section.end(); ++rIter)
            authority_section.push_back( (*rIter) );

        additional_section.clear();
        for( rIter = p.additional_section.begin(); rIter != p.additional_section.end(); ++rIter)
            additional_section.push_back( (*rIter) );

        return *this;
    }

    /*!
      Set the message id
      \param d Message id to assign to the message
      \return id
    */
    const uint16_t id(const uint16_t d)
    {
        header.Id = d;
        return  header.Id;
    }

    /*!
      Get the message id

      \return id
    */
    const uint16_t id() const
    {
        return  header.Id;
    }

    /*!
      Sets the Query action

      \param e Query action to assign to the message.
      \return query action
    */
    const action_t action(const action_t e)
    {
        (e == query) ?
                header.bit_fields &= ~0x8000 :
                header.bit_fields |= 0x8000;

        return (action_t)(header.bit_fields & 0x8000);
    }

    /*!
      Gets the Query action

      \return query action
    */
    const action_t action() const
    {
        return (action_t)(header.bit_fields & 0x8000);
    }


    /*!
      Sets the Opcode

      \param oc Opcode to assign to the message.
      \return Opcode
    */
    const opcode_t  opcode(const opcode_t oc)
    {
        switch( oc )
        {
            case squery:
                header.bit_fields &= ~0x3000;
                return squery;
            case iquery:
                header.bit_fields |= 0x1000;
                return iquery;
            case status:
                header.bit_fields |= 0x2000;
                return status;
            case no_opcode:
                break;
        }

        if( header.bit_fields & 0x1000 )
            return iquery;
        if( header.bit_fields & 0x2000 )
            return status;

        return squery;
    }

    /*!
      Gets the Opcode

      \return Opcode
    */
    const opcode_t  opcode() const
    {
        if( header.bit_fields & 0x1000 )
            return iquery;
        if( header.bit_fields & 0x2000 )
            return status;

        return squery;
    }

    /*!
      Sets the 'authority' field

      Setting the 'authority' field is a function used by servers that are answering a request.

      \param authority True if the server answering is the authority
    */
    void  authority(const bool authority)
    {
        (authority) ? header.bit_fields |= 0x400 :
                header.bit_fields &= ~0x400;
    }

    /*!
      Gets the 'authority' field

      \return True if the server answering is the authority
    */
    const bool is_authority() const
    {
        return( header.bit_fields & 0x400 );
    }

    /*!
      Sets the 'truncated' field.

      Setting the 'truncated' field  is a function used by servers to notify the
      client that message has been truncated, due to the large volume of answers.

      \param  truncated True if the server is truncating
    */
    void  truncated(const bool truncated)
    {
        (truncated) ? header.bit_fields |= 0x200 :
                header.bit_fields &= ~0x200;
    }

    /*!
      Gets the 'truncated' field

      \return True if the server is truncating the message
    */
    const bool is_truncated() const  { return( header.bit_fields & 0x200 ); }

    /*!
      Sets the 'recursive' field.

      Setting the 'recursive' field is a function used by clients to notify the
      server that message if the DNS question is not answerable by the server, the
      server can ask other DNS servers for a response.

      \param  recursive True if the server should recursively seek an answer.
    */
    void  recursive(const bool recursive)
    {
        (recursive) ? header.bit_fields |= 0x100 :
                header.bit_fields &= ~0x100;
    }

    /*!
      Gets the 'recursive' field.

      \return True if the server can recursively seek an answer.
    */
    const bool is_recursive() const  { return( header.bit_fields & 0x100 ); }

    /*!
      Sets the 'recursion availability' field.

      Setting the 'recursion availability' field is a function used by servers to notify the
      client that recursion is supported. Some servers are only authority servers and do not
      act as proxies when the domain does not reside with them.

      \param  recursion_avail True if the server can recursively seek an answer.
    */
    void  recursion_avail(const bool recursion_avail)
    {
        (recursion_avail) ? header.bit_fields |= 0x80 :
                header.bit_fields &= ~0x80;
    }

    /*!
      Gets the 'recursion availability' field.

      \return True if the server can recursively seek an answer.
    */
    const bool is_recursion_avail() const
    {
        return( header.bit_fields & 0x80 );
    }

    /*!
      Sets the result code for the message.

      \param r Result code to assign to the message
      \return Result code
    */
    const result_t result(const result_t r)
    {
        switch( r )
        {
            case noerror:
                header.bit_fields &= ~0x07;
                break;

            default:
                header.bit_fields |= r;
                break;
        }

        if( header.bit_fields & 0x01 )
            return format_error;

        if( header.bit_fields & 0x02 )
            return server_error;

        if( header.bit_fields & 0x03 )
            return name_error;

        if( header.bit_fields & 0x04 )
            return not_implemented;

        if( header.bit_fields & 0x05 )
            return refused;

        if( header.bit_fields & 0x06 )
            return no_result;

        return noerror;
    }

    /*!
      Gets the result code for the message.

      \return Result code
    */
    const result_t result() const
    {
        if( header.bit_fields & 0x01 )
            return format_error;

        if( header.bit_fields & 0x02 )
            return server_error;

        if( header.bit_fields & 0x03 )
            return name_error;

        if( header.bit_fields & 0x04 )
            return not_implemented;

        if( header.bit_fields & 0x05 )
            return refused;

        if( header.bit_fields & 0x06 )
            return no_result;

        return noerror;
    }

    /// Returns the questions container
    questions_t*        questions()   { return &question_section; }
    /// Returns the answers container
    rr_list_t*          answers()     { return &answer_section; }
    /// Returns the authorites container
    rr_list_t*          authorites()  { return &authority_section; }
    /// Returns the additionals container
    rr_list_t*          additionals() { return &additional_section; }

    /// Encodes the dns message into a memory buffer
    /*
      \param buffer Buffer to encode the message into
    */
    void  encode(dns_buffer_t& buffer)
    {
        // reset the buffer to the 0th position and reset the length
        buffer.position(0);

        rfc1035_414_t offset_map;

        buffer.put( header.Id );
        buffer.put( header.bit_fields );
        buffer.put( (uint16_t)question_section.size() );
        buffer.put( (uint16_t)answer_section.size() );
        buffer.put( (uint16_t)authority_section.size() );
        buffer.put( (uint16_t)additional_section.size() );

        questions_t::iterator qiter;
        for( qiter = question_section.begin(); qiter != question_section.end(); ++qiter )
            ((question)*qiter).encode(buffer, offset_map);

        rr_list_t::iterator riter;
        for( riter = answer_section.begin(); riter != answer_section.end(); ++riter )
            (*riter)->encode(buffer, offset_map);
        for( riter = authority_section.begin(); riter != authority_section.end(); ++riter )
            (*riter)->encode(buffer, offset_map);
        for( riter = additional_section.begin(); riter != additional_section.end(); ++riter )
            (*riter)->encode(buffer, offset_map);
    }

    /// Decodes the dns message into a memory buffer
    /*
      \param buffer Buffer to decode the message into
    */
    void  decode(dns_buffer_t& buffer)
    {
        try
        {

            // clean out the different sections
            question_section.erase(question_section.begin(), question_section.end());
            answer_section.erase(answer_section.begin(), answer_section.end());
            authority_section.erase(authority_section.begin(), authority_section.end());
            additional_section.erase(additional_section.begin(), additional_section.end());

            // start at 0th
            buffer.position(0);

            buffer.get( header.Id );
            buffer.get( header.bit_fields );
            buffer.get( header.QdCount );
            buffer.get( header.AnCount );
            buffer.get( header.NsCount );
            buffer.get( header.ArCount );

            rfc1035_414_t offset_map;

            // read the sections
            for( uint16_t i = 0; i < header.QdCount; ++ i )
                question_section.push_back( question(buffer, offset_map) );

            for( uint16_t i = 0; i < header.AnCount; ++ i )
                answer_section.push_back( unpack_record(buffer,offset_map) );

            for( uint16_t i = 0; i < header.NsCount; ++ i )
                authority_section.push_back( unpack_record(buffer,offset_map) );

            for( uint16_t i = 0; i < header.ArCount; ++ i )
                additional_section.push_back( unpack_record(buffer,offset_map) );
        }
        catch (...)
        {
            result( server_error );
        }
    }

  private:
    shared_resource_base_t unpack_record(dns_buffer_t& buffer, rfc1035_414_t& offset_map)
    {
        shared_resource_base_t  ptr;

        /*
          catch 22, can't decode a "type" unless we know the "type"
          So, we treat this as a pre-amble to the data and then decode the payload later
        */
        resource_base_t preamble;
        preamble.decode(buffer, offset_map);

        switch( preamble.rtype()  )
        {
            case type_a:
                {
                    dns::a_resource*  aPtr = new dns::a_resource(preamble);
                    aPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(aPtr);
                }
                break;
            case type_ns:
                {
                    dns::ns_resource*  nsPtr = new dns::ns_resource(preamble);
                    nsPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(nsPtr);
                }
                break;
            case type_cname:
                {
                    dns::cname_resource*  cnamePtr = new dns::cname_resource(preamble);
                    cnamePtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(cnamePtr);
                }
                break;
            case type_soa:
                {
                    dns::soa_resource*  soaPtr = new dns::soa_resource(preamble);
                    soaPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(soaPtr);
                }
                break;
            case type_ptr:
                {
                    dns::ptr_resource*  ptrPtr = new dns::ptr_resource(preamble);
                    ptrPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(ptrPtr);
                }
                break;
            case type_hinfo:
                {
                    dns::hinfo_resource*  hinfoPtr = new dns::hinfo_resource(preamble);
                    hinfoPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(hinfoPtr);
                }
                break;
            case type_mx:
                {
                    dns::mx_resource*  mxPtr = new dns::mx_resource(preamble);
                    mxPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(mxPtr);
                }
                break;
            case type_txt:
                {
                    dns::txt_resource*  txtPtr = new dns::txt_resource(preamble);
                    txtPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(txtPtr);
                }
                break;
            case type_a6:
                {
                    dns::a6_resource* a6Ptr = new dns::a6_resource(preamble);
                    a6Ptr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(a6Ptr);
                }
                break;
            case type_srv:
                {
                    dns::srv_resource*  srvPtr = new dns::srv_resource(preamble);
                    srvPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(srvPtr);
                }
                break;
            default:
                {
                    // An unknown record. Save the data and move on.
                    unknown_resource *unkPtr = new unknown_resource(preamble);
                    unkPtr->decode(buffer, offset_map);
                    ptr = shared_resource_base_t(unkPtr);
                }
                break;
        }

        return ptr;
    }
};

} // namespace dns
} // namespace net
} // namespace y
#include <boost/asio/detail/pop_options.hpp>

#endif // BOOST_NET_DNS_HPP
