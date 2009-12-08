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
#include <boost/archive/text_oarchive.hpp>


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
   /**
    * The constructor takes the name of the file and a flag representing the input
    * mode (live or offline).
    */
    SessionFinder(const char*, const char*);

  /**
   * Runs the input handler.
   */
    void run();

   /**
    * Handles a single Packet structure. Attempts to decode tracker requests,
    * responses, and piece messages. Any packet that is not one of the above
    * is discarded.
    */
    void handlePacket(Packet pkt);
private:

    //Get the session corresponding to a given host and tracker
    Session *findSession(std::string, u_short, std::string);
    //Find a session that has an activated peer on ip:port
    Session *findSession(std::string, u_short);

    //Output file stream
    std::ofstream output_pipe;

    //Input file stream
    std::ifstream input_pipe;

    //Input archive
    boost::archive::text_iarchive input_archive;

    //Output archive
    boost::archive::text_oarchive output_archive;

    //Map of session objects, indexed by info hash
    std::map<std::string, Session*> sessions;
};

#endif
// vim: tabstop=4:expandtab
