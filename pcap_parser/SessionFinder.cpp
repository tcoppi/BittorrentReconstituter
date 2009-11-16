/**
 * Implementation of the SessionFinder class.
 * 
 * Original Author: Aaron A. Lovato
 */

#include "SessionFinder.hpp"
#include "headers.hpp"
#include <iostream> 

using std::cout;
using std::cerr;
using std::endl;

/**
 * The constructor takes the name of the file and a flag representing the input
 * mode (live or offline).
 */
SessionFinder::SessionFinder(std::string source, bool live) {
    
    //Set the name of the input source
    input_name = std::string(source);
    
    //Set the mode
    this->live = live;
}

/**
 * Sets up the input handler.
 */
void SessionFinder::Init() {
    if(!live) {
        //Set up an offline input
        input_handle = pcap_open_offline(input_name.c_str(), errbuf);
        if(input_handle == NULL) {
            //Might want to throw an exception here?
            cerr << "Unable to open file " << input_name << ": " << errbuf
                    << endl;
            return;
        }
        //Make sure the data link layer is ethernet
        if (pcap_datalink(input_handle) != DLT_EN10MB) {
            cerr << "Not ethernet!" << endl;
            return;
        }
        //Process the input
        struct pcap_pkthdr header;
        const u_char * packet = pcap_next(input_handle, &header);
        while(packet != NULL) {
            handlePacket(packet, &header);
            packet = pcap_next(input_handle, &header);
        }
    }
    else {
        //TODO Set up live input
    }
}

/**
 * Callback function for pcap_loop. Handles each packet individually.
 */
void SessionFinder::handlePacket(const u_char *packet, const struct pcap_pkthdr *header) {
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
        //Failed sanity check, discard packet
        return;
    }
    
    //BitTorrent is only TCP (that we care about) so only decode TCP packets
    if(ip_header->ip_p == IPPROTO_TCP) {
        //Cast to TCP header
        tcp_header = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        
        //Sanity check on size of TCP header
        size_tcp = TH_OFF(tcp_header)*4;
        if (size_tcp < 20) {
            //Failed sanity check, discard packet
            return;
        }
        
        //Get the packet's payload
        raw_payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        payload = std::string(raw_payload);
    }
    else {
        //Not TCP, ignore this packet
        return;
    }
    

    //TODO BitTorrent identification
    
    //Find a GET with the required BitTorrent tracker request parameters
    if((payload.find("GET") != std::string::npos) && 
       (payload.find("info_hash") != std::string::npos)  &&
       (payload.find("peer_id") != std::string::npos) &&
       (payload.find("port") != std::string::npos) &&
       (payload.find("uploaded") != std::string::npos) &&
       (payload.find("downloaded") != std::string::npos) &&
       (payload.find("left") != std::string::npos)) {
        //Found a tracker request
        //TODO do something with this request
    }
    
}
