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

class PacketHandler {
    public:
        PacketHandler(std::string, bool);
        void run();
    
    private:
        void handlePacket(const u_char *packet, const struct pcap_pkthdr *header);
        std::string input_name;
        pcap_t* input_handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        bool live;
};

#endif
