// Class to hold a single BitTorrent session data
//
// Original Authors: Aaron A. Lovato and Thomas Coppi

#ifndef PCAP_PARSER_SESSION_H
#define PCAP_PARSER_SESSION_H

#include <vector>
#include <string>
#include <map>
#include <pcap.h>
#include "Piece.hpp"
#include "Peer.hpp"

class Session {
    public:
        Session();
        Session(std::string, std::string, std::string);
        void addTracker(std::string);
        bool hasTracker(std::string);
        std::string getHost();
        void addPeer(std::string, u_short);
        bool hasPeer(std::string, u_short);
        void activatePeer(std::string);
        void addPiece();

    private:
        std::string info_hash; /* url and bencoded, shouldn't matter since
                                * we don't *need* the raw value, just the
                                * fact that it is unique. */
        std::string host; //The receiving host's IP address

        std::vector<std::string> trackers; //IP addresses of trackers

         //The IPs of the peers in this transfer
        std::map<std::string, Peer> peers;
        std::vector<Piece> pieces; //The pieces transferred
        bool completed;
};

//TODO Add serialization code

#endif
