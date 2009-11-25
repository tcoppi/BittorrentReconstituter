#ifndef PCAP_PARSER_PEER_H
#define PCAP_PARSER_PEER_H

#include <string>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/string.hpp>

typedef struct {

    //IP address of this peer
    std::string ip;

    u_short port; // required

    //Whether this peer has completed a handshake to join the download
    bool active;
} Peer;

#endif