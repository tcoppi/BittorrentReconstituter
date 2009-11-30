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

#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>

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
        Peer *getPeer(std::string, u_short);
        void activatePeer(std::string);
        void addPiece(Piece*);
        Piece *getLastPiece();

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
        std::vector<Piece*> pieces;
        bool completed;
};

// Boost serialization
namespace boost {
    namespace serialization {
        template<class Archive>
        void serialize(Archive & ar, Session & s, const unsigned int version) {
            ar & s.info_hash;
            ar & s.host;
            ar & s.trackers;
            ar & s.peers;
            ar & s.pieces;
        }
    }
}
#endif
// vim: tabstop=4:expandtab
