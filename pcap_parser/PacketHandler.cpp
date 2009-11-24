/**
 * Reads packets from a libpcap input, either live or offline, decodes the
 * TCP/IP headers, creates Packet data structures to represent each packet,
 * and sends the Packets over a pipe to another process for parsing.
 *
 * Original Author: Aaron A. Lovato
 */

#include "PacketHandler.hpp"
#include "headers.hpp"
#include <iostream>

/**
 * The constructor takes the name of the file and a flag representing the input
 * mode (live or offline).
 */
PacketHandler::PacketHandler(std::string source, bool live)
    : input_name(source), live(live) {}

/**
 * Runs the input handler.
 */
void PacketHandler::run() {
    if (live) {
        //Set up a live input
        input_handle = pcap_open_live(input_name.c_str(), 65535, 1, 1000, errbuf);
        if (input_handle == NULL) {
            //Might want to throw an exception here?
            std::cerr << "Unable to open device " << input_name << ": " << errbuf
                    << std::endl;
            return;
        }
    }
    else {
        //Set up an offline input
        input_handle = pcap_open_offline(input_name.c_str(), errbuf);
        if (input_handle == NULL) {
            //Might want to throw an exception here?
            std::cerr << "Unable to open file " << input_name << ": " << errbuf
                    << std::endl;
            return;
        }
    }

    //Make sure the data link layer is ethernet
    if (pcap_datalink(input_handle) != DLT_EN10MB) {
        std::cerr << "Not ethernet!" << std::endl;
        return;
    }

    //Process the input
    struct pcap_pkthdr header;
    const u_char * packet = pcap_next(input_handle, &header);
    while (packet != NULL) {
        handlePacket(packet, &header);
        packet = pcap_next(input_handle, &header);
    }
}

/**
 * Function to process each packet from the input.
 */
void PacketHandler::handlePacket(const u_char *packet,
                                 const struct pcap_pkthdr *header) {
    //Packet headers
    const struct sniff_ethernet* ethernet_header;
    const struct sniff_ip* ip_header;
    const struct sniff_tcp* tcp_header;

    //Payload
    const char* raw_payload;
    std::string payload;

    //Keep track of packet sizes
    u_int size_ip;
    u_int size_tcp;

    //Cast to ethernet header
    ethernet_header = (struct sniff_ethernet*)(packet);

    //Cast to IP header
    ip_header = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    //Sanity check on size of IP header
    size_ip = IP_HL(ip_header)*4;
    if (size_ip < 20) {
        return; // Failed sanity check, discard packet
    }

    //BitTorrent is only TCP (that we care about) so only decode TCP packets
    if (ip_header->ip_p == IPPROTO_TCP) {
        //Cast to TCP header
        tcp_header = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

        //Sanity check on size of TCP header
        size_tcp = TH_OFF(tcp_header)*4;
        if (size_tcp < 20) {
            return; // Failed sanity check, discard packet
        }

        //Get the packet's payload
        raw_payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        payload = std::string(raw_payload);
    }
    else {
        return; // Not TCP, ignore this packet
    }
}
