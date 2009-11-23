/**
 * XXX Describe what SessionFinder does
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
SessionFinder::SessionFinder(std::string source, bool live)
    : input_name(source), live(live) {}

/**
 * Sets up the input handler.
 */
void SessionFinder::Init() {
    state = START;
    peer_index = 0;
    if (not live) {
        //Set up an offline input
        input_handle = pcap_open_offline(input_name.c_str(), errbuf);
        if (input_handle == NULL) {
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
    if (ip_header->ip_p == IPPROTO_TCP) {
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


    //TODO Break this out so it gets its data from a pipe after we are forked
    //out

    //XXX this makes no attempt to match up tracker requests and responses
    //since we are assuming they will come one right after each other(a safe
    //assumption I hope). Even if it is not, nothing should break

    //First thing, we need to look at tracker requests and responses
    //Find a GET with the required BitTorrent tracker request parameters
    //Tracker requests can be decoded anytime, regardless of the current state
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
	this->peer[peer_index].peer_id = std::string(raw_payload+offset, 20); //20 byte peer id

	offset = payload.find("port=");
	offset += strlen("port=");
	//find the & denoting the next parameter so we know where the end of
	//the int to convert is.
	endoff = payload.find("&", offset);
	this->peer[peer_index].port = (u_short)strtol(raw_payload+offset, raw_payload+endoff-1, 10);

	//XXX I don't believe uploaded and downloaded are necessary for our
	//purposes, not sure if left is either

	offset = payload.find("left=");
	offset += strlen("left=");
        endoff = payload.find("&", offset);
	this->peer[peer_index].left = (unsigned int)strtol(raw_payload+offset, raw_payload+endoff-1, 10);

	this->isreq = true;
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
	endoff = payload.find("e", offset); //the next 'e' after the i is where the integer ends
	this->num_seeders = (unsigned int)strtol(raw_payload+offset, raw_payload+offset+endoff-1, 10);

	//next thing we care about is the peer response. we will assume a
	//compact(non-dictionary) response since 99.9% of trackers use this now
	//this is in big-endian so we have to byteswap it
	offset = payload.find("5:peers");
	offset += strlen("5:peers");
	endoff = payload.find(":", offset); //get the next ':'
	//divide by 6 because each peer is 4 bytes for ip + 2 for port
	peers_to_add = (unsigned int)strtol(raw_payload+offset, raw_payload+offset+endoff-1, 10) /  6;

	offset = endoff+2; //skip over the ':'

	//peer looks like [4 byte ip][2 byte port] in network byte order
	//FIXME figure out a good way to translate to host order without all
	//kinds of conversions between string->int->string
	for(int i=0;i<peers_to_add;i++) {
	    //decode ip
	    this->peers[this->peer_index].ip = std::string(raw_payload+offset, 4);
	    //decode port
	    this->peers[this->peer_index].port = (u_short)strtol(raw_payload+offset+4, raw_payload+offset+6, 10);
	    this->peer_index++;
	}

	this->state = HAVE_TRACKER_RESPONSE;
    }
    //Move on to decoding bittorrent packets. We need to have at least found a
    //tracker request for this to happen.
    else if(this->state >= HAVE_TRACKER_REQUEST) {

    }

}
