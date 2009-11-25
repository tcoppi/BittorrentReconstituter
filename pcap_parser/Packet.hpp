/**
 * Structure to contain the relevant (for this project) parts of a
 * TCP/IP packet.
 *
 * Note: u_short was chosen for the port numbers because that is the data
 * type that libpcap uses for port numbers.
 *
 * Original Author: Aaron A. Lovato
 */
#ifndef PCAP_PARSER_PACKET_H
#define PCAP_PARSER_PACKET_H

#include <string>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/string.hpp>

/**
 *  Holds all the data in a packet that we need to pass to the SessionHandler.
 */
typedef struct {
    std::string src_ip;
    std::string dst_ip;
    u_short src_port;
    u_short dst_port;
    std::string payload;
} Packet;

// Non-instrusive Boost serialization
namespace boost {
    namespace serialization {

        template<class Archive>
                void serialize(Archive & ar, Packet & p, const unsigned int version)
        {
            ar & p.src_ip;
            ar & p.dst_ip;
            ar & p.src_port;
            ar & p.dst_port;
            ar & p.payload;
        }

    }
}

#endif
// vim: tabstop=4:expandtab
