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

class PacketHandler {
    public:
        PacketHandler(pcap_t*, const char*);
        void run();
    
    private:
        void handlePacket(const u_char *packet, const struct pcap_pkthdr *header);
        pcap_t* input_handle;
        std::ofstream output_pipe;
};
#endif
