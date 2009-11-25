/**
 * XXX Describe what SessionFinder does
 *
 * Original Author: Aaron A. Lovato
 */
#include "SessionFinder.hpp"
#include "headers.hpp"
#include "Peer.hpp"
#include <iostream>
#include <sstream>
#include <string.h>
#include <stdlib.h>
#include "Session.hpp"
#include "Packet.hpp"
using std::cout;
using std::cerr;
using std::endl;
/**
 * The constructor takes the name of the file and a flag representing the input
 * mode (live or offline).
 */
SessionFinder::SessionFinder(const char* input_name) {
    //Set up the input stream
    input_pipe.open(input_name);
}

/**
 * Sets up the input handler.
 */
void SessionFinder::run() {
    //Read each packet from the input pipe

    //Call handlePacket
}

/**
 * Handles a single Packet structure. Attempts to decode tracker requests,
 * responses, and piece messages. Any packet that is not one of the above
 * is discarded.
 */
void SessionFinder::handlePacket(Packet pkt) {
    //Temp vars
    unsigned int offset, endoff;

    //First thing, we need to look at tracker requests and responses
    //Find a GET with the required BitTorrent tracker request parameters
    //Tracker requests can be decoded anytime, regardless of the current state


    // XXX We can make this short circuit by changing it to a not and flipping
    // the !=s to ==s and the &&s to ||s, which will be faster.
    if((pkt.payload.find("GET") != std::string::npos) &&
       (pkt.payload.find("info_hash") != std::string::npos)  &&
       (pkt.payload.find("peer_id") != std::string::npos) &&
       (pkt.payload.find("port") != std::string::npos) &&
       (pkt.payload.find("uploaded") != std::string::npos) &&
       (pkt.payload.find("downloaded") != std::string::npos) &&
       (pkt.payload.find("left") != std::string::npos)) {
        //Found a tracker request

        //Extract out the content of each field
        //info_hash is unique for every transfer so it goes in the class
        offset = pkt.payload.find("info_hash=");
        offset += strlen("info_hash=");
	// FIXME we need to deurlencode and debencode this
        std::string info_hash = std::string(pkt.payload.c_str()+offset, 20); //20 byte info hash

        Session session = Session(pkt.dst_ip, pkt.src_ip, info_hash);

        offset = pkt.payload.find("port=");
        offset += strlen("port=");
        //Add the peer
        session.addPeer(pkt.src_ip, (u_short)strtol(pkt.payload.c_str()+offset, NULL, 10));

        //Add the session
        sessions[info_hash] = session;
    }
    //Decode a tracker response, need to have at least a tracker request first.
    else if((pkt.payload.find("HTTP") != std::string::npos) &&
            (pkt.payload.find("d8:complete"))) {
        //Find the corresponding session
        Session* session = findSession(pkt.dst_ip, pkt.src_ip);
        if(session == NULL) {
            return;
        }

        //next thing we care about is the peer response. we will assume a
        //compact(non-dictionary) response since 99.9% of trackers use this now
        //this is in big-endian so we have to byteswap it
        offset = pkt.payload.find("5:peers");
        offset += strlen("5:peers");
        endoff = pkt.payload.find(":", offset); //get the next ':'
        //divide by 6 because each peer is 4 bytes for ip + 2 for port
        unsigned int peers_to_add;
        peers_to_add = (unsigned int)strtol(pkt.payload.c_str()+offset, NULL, 10) /  6;

        offset = endoff+2; //skip over the ':'

        //peer looks like [4 byte ip][2 byte port] in network byte order
        //FIXME figure out a good way to translate to host order without all
        //kinds of conversions between string->int->string
        for(int i=0;i<peers_to_add;i++) {
            //decode ip
            session->addPeer(std::string(pkt.payload.c_str()+offset, 4),
            (u_short)strtol(pkt.payload.c_str()+offset+4, NULL, 10));

        }

    }
    //Decode a peer handshake
    else if((pkt.payload.find("BitTorrent protocol") != std::string::npos)) {
        offset = pkt.payload.find("BitTorrent protocol");
	offset += strlen("BitTorrent protocol") + 8; //skip over the 8 reserved bytes
	Session *session = findSession(std::string(pkt.payload.c_str()+offset,20)); //FIXME need a findSession that finds by the info_hash
	/* activate both because this handshake means both peers should be
	 * "alive"
	 */
	session->activatePeer(pkt.dst_ip);
	session->activatePeer(pkt.src_ip);
    }
    //Move on to decoding bittorrent packets. We need to have at least found a
    //tracker response for this to happen.
    else{
        //General plan of attack - check if the ip belongs to a peer we know
        //about and if it is on the right port. Then decode the packet as
        //bittorrent.

	//check if the src ip and port match a peer we know
	//src_idx = findPeerIP(ip_header->ip_src.s_addr);

	//if((src_idx == findPeerPort(tcp_header->th_sport)) && src_idx != 0) {
            //now check the dst ip and port
	    //dst_idx = findPeerIP(ip_header->ip_dst.s_addr);
	    //if((dst_idx == findPeerPort(tcp_header->th_dport)) && dst_idx != 0) {
		//this is a bittorrent packet
		//packet format looks like(network byte order)
		//[4-byte length][1 byte message ID][message-specific payload]
		//for PIECE messages, the data may be spread over more than one
		//tcp/ip packet, so we have to be sure to account for that.
	    //}
	}
}

//Gets a session associated with the given host and tracker
Session* SessionFinder::findSession(std::string host_ip,
                                   std::string tracker_ip) {
    std::map<std::string, Session>::iterator it;

    for(it = sessions.begin(); it != sessions.end(); it++) {
        if(((*it).second.getHost() == host_ip) and
              ((*it).second.hasTracker(tracker_ip))) {
            return &((*it).second);
        }
    }
    return NULL;

}
