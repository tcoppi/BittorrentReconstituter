/**
 * XXX Describe what SessionFinder does
 *
 * Original Author: Aaron A. Lovato
 */
#include <iostream>
#include <sstream>
#include <string.h>
#include <stdlib.h>
#include "SessionFinder.hpp"
#include "headers.hpp"
#include "Peer.hpp"
#include "Session.hpp"
#include "Packet.hpp"
using std::cout;
using std::cerr;
using std::endl;

// This function taken from http://www.boost.org/doc/libs/1_41_0/tools/inspect/link_check.cpp
// Copyright Beman Dawes 2002.
// Distributed under the Boost Software License, Version 1.0.
// Decode percent encoded characters, returns an empty string if there's an error.
std::string decode_percents(std::string const& url_path) {
    std::string::size_type pos = 0, next;
    std::string result;
    result.reserve(url_path.length());

    while((next = url_path.find('%', pos)) != std::string::npos) {
        result.append(url_path, pos, next - pos);
        pos = next;
        switch(url_path[pos]) {
        case '%': {
            if(url_path.length() - next < 3) return "";
            char hex[3] = { url_path[next + 1], url_path[next + 2], '\0' };
            char* end_ptr;
            result += (char) std::strtol(hex, &end_ptr, 16);
            if(*end_ptr) return "";
            pos = next + 3;
            break;
        }
        }
    }
    result.append(url_path, pos, url_path.length());

    return result;
}

/**
 * The constructor takes the name of the file and a flag representing the input
 * mode (live or offline).
 */
SessionFinder::SessionFinder(const char* pipe)
    : input_pipe(pipe), input_archive(input_pipe){
    }

/**
 * Runs the input handler.
 */
void SessionFinder::run() {
    // Read each packet from the input pipe
    Packet current;
    while (true) {
        try {
            input_archive >> current;
            //Call handlePacket
            handlePacket(current);
        }
        catch (boost::archive::archive_exception &e) {
            //Stop processing packets if a problem occurs
            //This exception covers both stream errors and EOF
            break;
        }
    }
}

/**
 * Handles a single Packet structure. Attempts to decode tracker requests,
 * responses, and piece messages. Any packet that is not one of the above
 * is discarded.
 */
void SessionFinder::handlePacket(Packet pkt) {
    unsigned int offset, endoff; // Temps

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

        //find the next field after info_hash
        int hash_size = pkt.payload.find("&") - offset;
        
        // The string is URL encoded, so we need to take out all the percents
        // and possibly ampersands.  info_hash is 20 bytes long.
        std::string info_hash = decode_percents(std::string(pkt.payload.c_str()+offset, hash_size));
        std::cout << "saving a session with length " << info_hash.size() << std::endl;
        Session *session = new Session(pkt.dst_ip, pkt.src_ip, info_hash);

        offset = pkt.payload.find("port=");
        offset += strlen("port=");

        // Add the peer - doesn't make sense to add host as peer
/*        session->addPeer(pkt.src_ip, (u_short)strtol(pkt.payload.c_str()+offset, NULL, 10));*/
        
        //trace statements
        std::cout << "got a request from " << pkt.src_ip << std::endl;
        std::cout << "info hash: " << info_hash << std::endl;
        std::cout << "payload: " << pkt.payload << std::endl;

        
        // Add the session
        sessions[info_hash] = session;
    }
    //Decode a tracker response, need to have at least a tracker request first.
    else if((pkt.payload.find("HTTP") != std::string::npos) &&
            (pkt.payload.find("d8:complete"))) {
        //Find the corresponding session
        Session *session = findSession(pkt.dst_ip, pkt.src_ip);
        if (session == NULL) {
            std::cout << "didn't find a session" << std::endl;
            return; 
        }

        std::cout << "got a response from " << pkt.dst_ip << std::endl;
        
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
        for(int i=0;i<peers_to_add;i++) {
            //decode ip
            std::cout << "adding peer " << std::string(pkt.payload.c_str()+offset, 4) << " to session " << session->getHash() << std::endl;
            
            session->addPeer(std::string(pkt.payload.c_str()+offset, 4),
            (u_short)strtol(pkt.payload.c_str()+offset+4, NULL, 10));
        }
    }
    //Decode a peer handshake by finding the "BitTorrent protocol" string
    else if((pkt.payload.find("BitTorrent protocol") != std::string::npos)) {
        
        //Found a handshake packet
        offset = pkt.payload.find("BitTorrent protocol");
        offset += strlen("BitTorrent protocol") + 8; //skip over the 8 reserved bytes
        
        //The info_hash is the 20 bytes following the reserved byts
        std::string hash = std::string(pkt.payload.c_str()+offset, 20);
        //Get rid of trailing data
//         hash.erase(20);
        std::cout << "getting a session with hash length" << hash.size() << std::endl;

        //Get session from hash
        std::map<std::string, Session*>::iterator found;
        found = sessions.find(hash);
        if(found == sessions.end()) {
            std::cout << "didn't find a session" << std::endl;
            return;
        }
        Session *session = found->second;
        std::cout << "found a piece with info_hash" << std::endl;
        // Activate both because this handshake means both peers should be alive
        session->activatePeer(pkt.src_ip);
    }
    //Move on to decoding bittorrent packets. We need to have at least found a
    //tracker response for this to happen.
    else {
        /* General plan of attack - check if the ip belongs to a peer we know
         * about, is active, and if it is on the right port. Then decode the
         * packet as bittorrent.
         */

        //Find a session with the source as a peer
        Session *session = findSession(pkt.src_ip, pkt.src_port);
        if (session == NULL) {
            return;
        }
        
        //Make sure the destination ip matches the host
        if(pkt.dst_ip != session->getHost()) {
            return;
        }
        
        //Make sure the peer corresponding to the source is active
        Peer* source = session->getPeer(pkt.src_ip, pkt.src_port);
        if (!source->active) {
            //The peer isn't active, drop this packet
            return;
        }
        
        //Continue a piece in flight
        if(not session->getLastPiece()->isCompleted()) {
            //Update last piece
            session->getLastPiece()->addPayload(pkt.payload);
            return;
        }
        
        //This packet should correspond to session
        //Attempt to decode it as a Piece message
        Piece * piece = new Piece(pkt.payload);
        if(not piece->isValid()) {
            return;
        }
        
        //Add piece to session
        session->addPiece(piece);
	}
}

/**
 * Gets a session associated with the given host and tracker.
 */
Session *SessionFinder::findSession(std::string host_ip,
                                    std::string tracker_ip) {
    std::map<std::string, Session*>::iterator it;
    for (it = sessions.begin(); it != sessions.end(); ++it) {
        if ((it->second->getHost() == host_ip) and
            (it->second->hasTracker(tracker_ip))) {
            return it->second;
        }
    }
    return NULL;
}

Session *SessionFinder::findSession(std::string ip, u_short port) {
    std::map<std::string, Session*>::iterator it;
    for (it = sessions.begin(); it != sessions.end(); ++it) {
        if (it->second->hasPeer(ip, port)) {
            return it->second;
        }
    }
    return NULL;
}
// vim: tabstop=4:expandtab
