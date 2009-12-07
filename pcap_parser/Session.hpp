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

typedef std::map<std::string,std::vector<Piece*> > ip_piece_map_t;

/**
 * Stores everything we know about a BitTorrent session.
 *
 * A session is uniquely identified by a info_hash obtained from the tracker
 * and subsequently from the peer handshakes.
 */
class Session {
    public:
        Session();
        Session(std::string, u_short, std::string, std::string);
        void addTracker(std::string);
        bool hasTracker(std::string);

        std::string getHost();
        std::string getHash();
        Peer *getPeer(std::string, u_short);
        u_short getHostPort();
        Piece *getLastPiece(std::string ip);
        ip_piece_map_t getPieces() { return this->pieces; }
        std::map<std::string, Peer> getPeers();
        std::vector<unsigned int> getUploadedIndices() { return this->uploaded; }

        void addPeer(std::string, u_short);
        bool hasPeer(std::string, u_short);
        void activatePeer(std::string);
        void addPiece(std::string ip, Piece*);
        void addUploadedIndex(unsigned int);
        void setCompleted(bool);

    private:
        friend std::ostream & operator<<(std::ostream &, const Session &);
        friend class boost::serialization::access;
        template<class Archive>
        void serialize(Archive & ar, const unsigned int){
            ar & info_hash & host & trackers & peers & pieces;
        }

        std::string info_hash; /* url and bencoded, shouldn't matter since
                                * we don't *need* the raw value, just the
                                * fact that it is unique. */

        //The receiving host's IP address and port
        std::string host;
        u_short host_port;

        //IP addresses of trackers
        std::vector<std::string> trackers;

        //The IPs of the peers in this transfer
        std::map<std::string, Peer> peers;

        //The pieces received
        ip_piece_map_t pieces;

        //The indexes of pieces uploaded
        std::vector<unsigned int> uploaded;

        bool completed;
};

#endif
// vim: tabstop=4:expandtab
