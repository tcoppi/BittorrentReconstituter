/**
 * This class represents a module that parses a pcap file and identifies
 * BitTorrent sessions.
 *
 * Original Author: Aaron A. Lovato
 */

#ifndef PCAP_PARSER_PACKET_HANDLER_H
#define PCAP_PARSER_PACKET_HANDLER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <fstream>

/**
 * Creates packets one by one from pcap and passes them on to the
 * SessionHandler.
 */
class PacketHandler {
    public:
        /**
        * The constructor takes the name of the file and a flag representing the input
        * mode (live or offline).
        */
        PacketHandler(pcap_t*, const char*);

        /**
         * Runs the input handler.
         */
        void run();

    private:
        /**
         * Function to process each packet from the input.
         */
        void handlePacket(const u_char *packet, const struct pcap_pkthdr *header);
        pcap_t* input_handle;
        std::ofstream output_pipe;
};
#endif
// vim: tabstop=4:expandtab
