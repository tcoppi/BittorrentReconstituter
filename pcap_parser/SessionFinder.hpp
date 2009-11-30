/**
 * This class takes Packets from the PacketHandler and forms Sessions
 *
 * Original Author: Aaron A. Lovato
 */
#ifndef PCAP_PARSER_SESSION_FINDER_H
#define PCAP_PARSER_SESSION_FINDER_H

#include "Packet.hpp"
#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <stdbool.h>
#include <arpa/inet.h>
#include <fstream>
#include "Piece.hpp"
#include "Session.hpp"
#include <boost/archive/text_iarchive.hpp>


/* IDs of the bittorrent messages we might care about */
#define CHOKE 0
#define UNCHOKE 1
#define INTERESTED 2
#define NINTERESTED 3
#define HAVE 4
#define REQUEST 6
#define PIECE 7

/**
 * Take packets from the PacketHandler and form Sessions.
 */
class SessionFinder {
public:
    SessionFinder(const char*, const char*);
    void run();
    void handlePacket(Packet pkt);
private:

    //Get the session corresponding to a given host and tracker
    Session *findSession(std::string, u_short, std::string);
    //Find a session that has an activated peer on ip:port
    Session *findSession(std::string, u_short);

    /**
     * Since a piece can be too large for one packet, we need to keep some
     * state about the current piece that is being reconstructed.
     */
    Piece *currpiece;

    /**
     * Tells us if we are continuing a piece from a previous packet.
     */
    bool piece_in_flight;

    /**
     * Total length of the piece. When the piece we are building has a length
     * equal to this we are done.
     */
    unsigned int total_len;

    //Input file stream
    std::ifstream input_pipe;

    //Input archive
    boost::archive::text_iarchive input_archive;

    //Map of session objects, indexed by info hash
    std::map<std::string, Session*> sessions;
};

#endif
// vim: tabstop=4:expandtab
