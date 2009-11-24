/**
 * XXX Describe what SessionFinder does
 *
 * Original Author: Aaron A. Lovato
 */
#include "SessionFinder.hpp"
#include "headers.hpp"
#include <iostream>
#include <sstream>
#include <string.h>
#include <stdlib.h>

using std::cout;
using std::cerr;
using std::endl;

// Returns the the index of the peer with this IP
unsigned int SessionFinder::findPeerIP(unsigned int ip) {
    for (int i=0; i < this->peer_index; i++) {
        if (this->peers[this->peer_index].ipi == ip)
            return i;
    }
    return 0;
}

// Returns the index of the first peer with this port number
// XXX This return value, while technically correct, should be unsigned int as well,
// unless there's a good reason it's not.
u_short SessionFinder::findPeerPort(u_short port) {
    for(int i=0; i < this->peer_index; i++) {
        if (this->peers[this->peer_index].port == port)
            return i;
    }
    return 0;
}

/**
 * The constructor takes the name of the file and a flag representing the input
 * mode (live or offline).
 */
SessionFinder::SessionFinder(std::string source, bool live)
    : input_name(source), live(live) {}

/**
 * Sets up the input handler.
 */
void SessionFinder::Init() {
    std::stringstream err;
    this->state = START;
    this->peer_index = 0;

    if (not this->live) {
        //Set up an offline input
        this->input_handle = pcap_open_offline(input_name.c_str(), errbuf);
        if (this->input_handle == NULL) {
            err << "Unable to open file " << input_name << ": " << errbuf
                << endl;
            throw err.str();
        }
        //Make sure the data link layer is ethernet
        if (pcap_datalink(input_handle) != DLT_EN10MB) {
            err << "Not ethernet!" << endl;
            throw err.str();
        }
        //Process the input
        struct pcap_pkthdr header;
        const u_char * packet = pcap_next(input_handle, &header);
        while (packet != NULL) {
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
void SessionFinder::handlePacket(const u_char *packet,
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

    //Temp vars
    size_t offset, endoff;
    unsigned int peers_to_add;
    unsigned int src_idx, dst_idx;
    char *inet_tmp;

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


    //TODO Break this out so it gets its data from a pipe after we are forked
    //out

    //XXX this makes no attempt to match up tracker requests and responses
    //since we are assuming they will come one right after each other(a safe
    //assumption I hope). Even if it is not, nothing should break

    //First thing, we need to look at tracker requests and responses
    //Find a GET with the required BitTorrent tracker request parameters
    //Tracker requests can be decoded anytime, regardless of the current state

    // XXX We can make this short circuit by changing it to a not and flipping
    // the !=s to ==s and the &&s to ||s, which will be faster.
    if((payload.find("GET") != std::string::npos) &&
       (payload.find("info_hash") != std::string::npos)  &&
       (payload.find("peer_id") != std::string::npos) &&
       (payload.find("port") != std::string::npos) &&
       (payload.find("uploaded") != std::string::npos) &&
       (payload.find("downloaded") != std::string::npos) &&
       (payload.find("left") != std::string::npos)) {
        //Found a tracker request

        //Extract out the content of each field
        //info_hash is unique for every transfer so it goes in the class
        offset = payload.find("info_hash=");
        offset += strlen("info_hash=");
        this->info_hash = std::string(raw_payload+offset, 20); //20 byte info hash

        offset = payload.find("peer_id=");
        offset += strlen("peer_id=");
        this->peers[peer_index].peer_id = std::string(raw_payload+offset, 20); //20 byte peer id

        offset = payload.find("port=");
        offset += strlen("port=");
        // It doesn't look like we're actually using the second param here and
        // it gives us compile errors. This should be payload if we do need the
        // behavior of a mutable reference there. I'm leaving it in for now,
        // anyway.
        this->peers[peer_index].port = (u_short)strtol(raw_payload+offset, NULL, 10);

        //XXX I don't believe uploaded and downloaded are necessary for our
        //purposes, not sure if left is either

        offset = payload.find("left=");
        offset += strlen("left=");
        this->peers[peer_index].left = (unsigned int)strtol(raw_payload+offset, NULL, 10);

        //set the peer's ip
        inet_tmp = (char*)malloc(256);
        if (not inet_tmp) {
            throw "Couldn't allocate memory, your system is borked.";
        }
        inet_ntop(AF_INET, &(ip_header->ip_src), inet_tmp, 255);
        this->peers[peer_index].ip = std::string(inet_tmp);
        free(inet_tmp);

        this->peers[peer_index].ipi = ip_header->ip_src.s_addr;

        this->peers[peer_index].isreq = true;
        peer_index++;

        this->state = HAVE_TRACKER_REQUEST;
    }
    //Decode a tracker response, need to have at least a tracker request first.
    else if((this->state >= HAVE_TRACKER_REQUEST) &&
            (payload.find("HTTP") != std::string::npos) &&
            (payload.find("d8:complete"))) {
        //do a limited form of bencode parsing, just enough to make this work
        offset = payload.find("d8:complete");
        offset += strlen("d8:complete") + 1; //add one for the 'i' indicating integer
        this->num_seeders = (unsigned int)strtol(raw_payload+offset, NULL, 10);

        //next thing we care about is the peer response. we will assume a
        //compact(non-dictionary) response since 99.9% of trackers use this now
        //this is in big-endian so we have to byteswap it
        offset = payload.find("5:peers");
        offset += strlen("5:peers");
        endoff = payload.find(":", offset); //get the next ':'
        //divide by 6 because each peer is 4 bytes for ip + 2 for port
        peers_to_add = (unsigned int)strtol(raw_payload+offset, NULL, 10) /  6;

        offset = endoff+2; //skip over the ':'

        //peer looks like [4 byte ip][2 byte port] in network byte order
        //FIXME figure out a good way to translate to host order without all
        //kinds of conversions between string->int->string
        for(int i=0;i<peers_to_add;i++) {
            //decode ip
            this->peers[this->peer_index].ip = std::string(raw_payload+offset, 4);
            this->peers[this->peer_index].ipi = (unsigned int)strtol(raw_payload+offset, NULL, 10);
            //decode port
            this->peers[this->peer_index].port = (u_short)strtol(raw_payload+offset+4, NULL, 10);
            this->peer_index++;
        }

        this->state = HAVE_TRACKER_RESPONSE;
    }
    //Move on to decoding bittorrent packets. We need to have at least found a
    //tracker response for this to happen.
    else if(this->state >= HAVE_TRACKER_RESPONSE) {
        //General plan of attack - check if the ip belongs to a peer we know
        //about and if it is on the right port. Then decode the packet as
        //bittorrent.

	//check if the src ip and port match a peer we know
	src_idx = findPeerIP(ip_header->ip_src.s_addr);

	if((src_idx == findPeerPort(tcp_header->th_sport)) && src_idx != 0) {
            //now check the dst ip and port
	    dst_idx = findPeerIP(ip_header->ip_dst.s_addr);
	    if((dst_idx == findPeerPort(tcp_header->th_dport)) && dst_idx != 0) {
		//this is a bittorrent packet
		//packet format looks like(network byte order)
		//[4-byte length][1 byte message ID][message-specific payload]
		//for PIECE messages, the data may be spread over more than one
		//tcp/ip packet, so we have to be sure to account for that.
	    }
	}
    }
}
