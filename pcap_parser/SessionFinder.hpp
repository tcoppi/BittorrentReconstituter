/**
 * This class represents a module that parses a pcap file and identifies
 * BitTorrent sessions.
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


/* IDs of the bittorrent messages we might care about */
#define CHOKE 0
#define UNCHOKE 1
#define INTERESTED 2
#define NINTERESTED 3
#define HAVE 4
#define REQUEST 6
#define PIECE 7

class SessionFinder {
public:
    SessionFinder(const char*);
    void run();
    void handlePacket(Packet pkt);
private:

    //Get the session corresponding to a given host and tracker
    Session* findSession(std::string, std::string);
    
    //Input file stream
    std::ifstream input_pipe;
    
    //Map of session objects
    std::map<std::string, Session> sessions;
};

#endif
