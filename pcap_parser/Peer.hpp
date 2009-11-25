#ifndef PCAP_PARSER_PEER_H
#define PCAP_PARSER_PEER_H

#include <string>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/string.hpp>

/**
 * Stores everything we need about Peers we find.
 */
typedef struct {
    std::string ip;
    u_short port;

    //Whether this peer has completed a handshake to join the download
    bool active;
} Peer;

#endif
// vim: tabstop=4:expandtab
