#ifndef GREYLISTING_OPTIONS_H
#define GREYLISTING_OPTIONS_H

#include <vector>
#include <algorithm>
#include <boost/program_options.hpp>
#include <time.h>
#include "host_seq_resolver.h"

struct greylisting_options
{
    std::string ns;
    bool use_ip;
    bool use_envelope_from;
    bool use_envelope_to;
    bool use_header_from;
    bool use_header_to;
    bool use_header_messageid;
    bool use_header_subject;
    bool use_header_date;
    bool use_body;
    int window_hit_threshold;
    ::time_t window_begin;
    ::time_t window_end;
    ::time_t record_lifetime;
    ::time_t udp_timeout;
    int udp_port;
    std::vector<boost::asio::ip::udp::endpoint> hosts;
};

struct greylisting_options_parser
{
    greylisting_options& p;
    greylisting_options_parser(greylisting_options& opt)
            : p(opt)
    {}

    void parse_from_file(const char* filename)
    {
        namespace bpo = boost::program_options;
        bpo::options_description descr("greylisting options");
        bpo::variables_map vm;
        std::vector<std::string> hosts;
        descr.add_options()
                ("ns", bpo::value<std::string>(&p.ns)->default_value("gr"), "ns")
                ("use_ip", bpo::value<bool>(&p.use_ip)->default_value(false), "use client ip address (yes/no)")
                ("use_envelope_from", bpo::value<bool>(&p.use_envelope_from)->default_value(true), "use envelope from (yes/no)")
                ("use_envelope_to", bpo::value<bool>(&p.use_envelope_to)->default_value(true), "use envelope to (yes/no)")
                ("use_header_from", bpo::value<bool>(&p.use_header_from)->default_value(true), "use header from")
                ("use_header_to", bpo::value<bool>(&p.use_header_to)->default_value(true), "use header to")
                ("use_header_messageid", bpo::value<bool>(&p.use_header_messageid)->default_value(true), "use header messageid")
                ("use_header_subject", bpo::value<bool>(&p.use_header_subject)->default_value(true), "use header subject")
                ("use_header_date", bpo::value<bool>(&p.use_header_date)->default_value(true), "use header date")
                ("use_body", bpo::value<bool>(&p.use_body)->default_value(false), "use body")
                ("window_hit_threshold", bpo::value<int>(&p.window_hit_threshold)->default_value(2), "window hit threshold")
                ("window_begin", bpo::value<time_t>(&p.window_begin)->default_value(1200), "window begin")
                ("window_end", bpo::value<time_t>(&p.window_end)->default_value(14400), "window end")
                ("record_lifetime", bpo::value<time_t>(&p.record_lifetime)->default_value(604800), "record lifetime")
                ("udp_timeout", bpo::value<time_t>(&p.udp_timeout)->default_value(5), "udp timeout")
                ("udp_port", bpo::value<int>(&p.udp_port)->default_value(8890), "udp port")
                ("host", bpo::value<std::vector<std::string> >(&hosts)->required(), "rcsrv hosts")
                ;
        bpo::store(bpo::parse_config_file<char>(filename, descr, false), vm);
        bpo::notify(vm);

        resolve_host_sequence<boost::asio::ip::udp::endpoint>(hosts.begin(), hosts.end(),
                std::back_inserter(p.hosts), p.udp_port);
        std::sort(p.hosts.begin(), p.hosts.end());
    }
};

#endif // GREYLISTING_OPTIONS_H
