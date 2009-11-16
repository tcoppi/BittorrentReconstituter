/**
 * This class represents a module that parses a pcap file and identifies
 * BitTorrent sessions.
 * 
 * Original Author: Aaron A. Lovato
 */

#ifndef PCAP_PARSER_SESSION_FINDER_H
#define PCAP_PARSER_SESSION_FINDER_H

#include <pcap.h>
#include <string>
#include <vector>

class SessionFinder {
public:
    void Init(); // Use this instead of the constructor
    
private:
    SessionFinder(std::string, bool);
    void handlePacket(const u_char *packet, const struct pcap_pkthdr *header);
    std::string input_name;
    pcap_t* input_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bool live;
};

#endif
