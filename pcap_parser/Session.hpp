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

/**
 * Stores everything we know about a BitTorrent session.
 *
 * A session is uniquely identified by a info_hash obtained from the tracker
 * and subsequently from the peer handshakes.
 */
class Session {
    public:
        Session();
        Session(std::string, std::string, std::string);
        void addTracker(std::string);
        bool hasTracker(std::string);
        std::string getHost();
	    std::string getHash();
        void addPeer(std::string, u_short);
        bool hasPeer(std::string, u_short);
        void activatePeer(std::string);
        void addPiece();

    private:
        std::string info_hash; /* url and bencoded, shouldn't matter since
                                * we don't *need* the raw value, just the
                                * fact that it is unique. */
        //The receiving host's IP address
        std::string host;
        //IP addresses of trackers
        std::vector<std::string> trackers;

         //The IPs of the peers in this transfer
        std::map<std::string, Peer> peers;
        //The pieces transferred
        std::vector<Piece> pieces;
        bool completed;
};

//TODO Add serialization code

#endif
// vim: tabstop=4:expandtab
