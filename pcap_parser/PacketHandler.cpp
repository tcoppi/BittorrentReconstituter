/**
 * Reads packets from a libpcap input, either live or offline, decodes the
 * TCP/IP headers, creates Packet data structures to represent each packet,
 * and sends the Packets over a pipe to another process for parsing.
 *
 * Original Author: Aaron A. Lovato
 */

#include "PacketHandler.hpp"
#include "headers.hpp"
#include "Packet.hpp"
#include "Piece.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>

PacketHandler::PacketHandler(pcap_t* handler, const char* pipe)
    : input_handle(handler), output_pipe(pipe), output_archive(output_pipe) {}

void PacketHandler::run() {
    //Process the input
    struct pcap_pkthdr header;
    const u_char *packet = pcap_next(input_handle, &header);
    while (packet != NULL) {
        handlePacket(packet, &header);
        packet = pcap_next(input_handle, &header);
    }
    output_pipe.close();
}

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
        payload = std::string(raw_payload, (ntohs(ip_header->ip_len) - (size_ip + size_tcp)));
//         std::cout << payload << std::endl;
    }
    else {
        return; // Not TCP, ignore this packet
    }

    //Create Packet object
    Packet pkt;
    pkt.src_ip = std::string(inet_ntoa(ip_header->ip_src));
    pkt.dst_ip = std::string(inet_ntoa(ip_header->ip_dst));
    pkt.src_port = ntohs(tcp_header->th_sport);
    pkt.dst_port = ntohs(tcp_header->th_dport);
    pkt.payload = std::string(payload);

//     std::cout << "writing payload " << pkt.payload << std::endl;

    //Serialize packet to output pipe
    output_archive << pkt;
    output_pipe.flush();
//
}
// vim: tabstop=4:expandtab
