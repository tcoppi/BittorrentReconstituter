/**
 * The SessionFinder reads Packet objects from a pipe and processes them to
 * identify BitTorrent Sessions. Session objects are created and written to a
 * pipe for processing.
 *
 * Original Authors: Thomas Coppi, Aaron A. Lovato, and Charlie Moore
 */

#include <iostream>
#include <sstream>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "SessionFinder.hpp"
#include "headers.hpp"
#include "Peer.hpp"
#include "Session.hpp"
#include "Packet.hpp"

/**
 * This function taken from
 * http://www.boost.org/doc/libs/1_41_0/tools/inspect/link_check.cpp
 * Copyright Beman Dawes 2002.  Distributed under the Boost Software License,
 * Version 1.0.
 * Decode percent encoded characters, returns an empty string if there's an error.
 */
static std::string decode_percents(std::string const& url_path) {
        std::string::size_type pos = 0, next; std::string result;
        result.reserve(url_path.length());

    while ((next = url_path.find('%', pos)) != std::string::npos) {
        result.append(url_path, pos, next - pos);
        pos = next;
        switch(url_path[pos]) {
        case '%': {
            if (url_path.length() - next < 3) return "";
            char hex[3] = { url_path[next + 1], url_path[next + 2], '\0' };
            char* end_ptr;
            result += (char) std::strtol(hex, &end_ptr, 16);
            if (*end_ptr) return "";
            pos = next + 3;
            break;
        }
        }
    }
    result.append(url_path, pos, url_path.length());

    return result;
}

SessionFinder::SessionFinder(const char* in_pipe, const char * out_pipe)
    : output_pipe(out_pipe), input_pipe(in_pipe), input_archive(input_pipe),
      output_archive(output_pipe){
    }

void SessionFinder::run() {

    //Write and endl to pipe to wake up other side
    output_pipe << std::endl;

    // Read each packet from the input pipe
    Packet current;
    while (true) {
        try {
            input_archive >> current;
            handlePacket(current);
        }

        catch (boost::archive::archive_exception &e) {
            //Stop processing packets if a problem occurs
            //This exception covers both stream errors and EOF
            break;
        }
    }
    input_pipe.close();
    output_pipe.close();
}

void SessionFinder::handlePacket(Packet pkt) {

    unsigned int offset, endoff; // Temps
    static Session *need_response = NULL;

    //First thing, we need to look at tracker requests and responses
    //Find a GET with the required BitTorrent tracker request parameters
    //Tracker requests can be decoded anytime, regardless of the current state

    // XXX We can make this short circuit by changing it to a not and flipping
    // the !=s to ==s and the &&s to ||s, which will be faster.
    if ((pkt.payload.find("GET") != std::string::npos) &&
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
        if (pkt.payload.find("started") != std::string::npos) {
            Session *session = new Session(pkt.src_ip, pkt.src_port, pkt.dst_ip, info_hash);

            offset = pkt.payload.find("port=");
            offset += strlen("port=");

            // Add the session
            sessions[info_hash] = session;
        }
        else if ((pkt.payload.find("completed") != std::string::npos) or
                (pkt.payload.find("stopped") != std::string::npos)) {
            //Get session
            //Extract out the content of each field
            //info_hash is unique for every transfer so it goes in the class
            offset = pkt.payload.find("info_hash=");
            offset += strlen("info_hash=");

            //find the next field after info_hash
            int hash_size = pkt.payload.find("&") - offset;

            // The string is URL encoded, so we need to take out all the percents
            // and possibly ampersands.  info_hash is 20 bytes long.
            std::string info_hash = decode_percents(
                    std::string(pkt.payload.c_str()+offset, hash_size));

            std::map<std::string, Session*>::iterator it =
                    sessions.find(info_hash);
            if (it == sessions.end()) {
                //Didn't find a session with this info hash, discard packet
                return;
            }
            Session * session = it->second;

            //Set completed
            session->setCompleted(true);

            //Remove from map
            sessions.erase(session->getHash());

            //Write to output
            output_archive << (*session);
            output_pipe << std::endl;

        }
        // this is a regular tracker request used to get peers
        else {
            //Get session
            //Extract out the content of each field
            //info_hash is unique for every transfer so it goes in the class
            offset = pkt.payload.find("info_hash=");
            offset += strlen("info_hash=");

            //find the next field after info_hash
            int hash_size = pkt.payload.find("&") - offset;

            // The string is URL encoded, so we need to take out all the percents
            // and possibly ampersands.  info_hash is 20 bytes long.
            std::string info_hash = decode_percents(
                    std::string(pkt.payload.c_str()+offset, hash_size));

            std::map<std::string, Session*>::iterator it =
                    sessions.find(info_hash);
            if (it == sessions.end()) {
                //Didn't find a session with this info hash, discard packet
                return;
            }
            need_response = it->second;
        }
    }
    //Decode a tracker response, need to have at least a tracker request first.
    else if ((pkt.payload.find("HTTP") != std::string::npos) &&
            (pkt.payload.find("5:peers") != std::string::npos)) {
        //Find the corresponding session
        Session *session;
        if (need_response != NULL) {
            session = need_response;
        }
        else {
            session = findSession(pkt.dst_ip, pkt.dst_port, pkt.src_ip);
            if (session == NULL) {
                return;
            }
        }

        //next thing we care about is the peer response. we will assume a
        //compact(non-dictionary) response since 99.9% of trackers use this now
        //this is in big-endian so we have to byteswap it
        offset = pkt.payload.find("5:peers");
        offset += strlen("5:peers");

        endoff = pkt.payload.find(":", offset); //get the next ':'

        //divide by 6 because each peer is 4 bytes for ip + 2 for port
        unsigned int peers_to_add = atoi(pkt.payload.substr(offset, endoff-offset).c_str());
        peers_to_add /= 6;

        offset = endoff+1; //skip over the ':'

        //peer looks like [4 byte ip][2 byte port] in network byte order
        for (u_int i=0;i<peers_to_add;i++) {
            char *inet_tmp = (char *)malloc(16);
            const char *raw_data = pkt.payload.substr(offset, offset + 4).data();
            if (not inet_tmp)
                    throw "Out of memory";

            //decode ip and port
            snprintf(inet_tmp, 16, "%d.%d.%d.%d", (u_char)raw_data[0], (u_char)raw_data[1],
                     (u_char) raw_data[2], (u_char)raw_data[3]);
            raw_data = pkt.payload.c_str()+offset+4;
            unsigned short port = 0;
            port = ((u_char) raw_data[0] << 8) | (u_char) raw_data[1];

            session->addPeer(std::string(inet_tmp), port);

            offset += 6;
            free(inet_tmp);

        }
    }
    //Decode a peer handshake by finding the "BitTorrent protocol" string
    else if ((pkt.payload.find("BitTorrent protocol") != std::string::npos)) {
        //Found a handshake packet
        offset = pkt.payload.find("BitTorrent protocol");
        offset += strlen("BitTorrent protocol") + 8; //skip over the 8 reserved bytes

        //The info_hash is the 20 bytes following the reserved byts
        std::string hash = std::string(pkt.payload.c_str()+offset, 20);

        //Get session from hash
        std::map<std::string, Session*>::iterator found;
        found = sessions.find(hash);
        if (found == sessions.end()) {
            return;
        }
        Session *session = found->second;

        // Activate peer because this handshake means it should be alive
        session->activatePeer(pkt.src_ip);
    }
    //Move on to decoding bittorrent packets. We need to have at least found a
    //tracker response for this to happen.
    else {
        /* General plan of attack - check if the ip belongs to a peer we know
         * about, is active, and if it is on the right port. Then decode the
         * packet as bittorrent.
         */

        bool upload = false;

        //Find a session with the source as a peer
        Session *session = findSession(pkt.src_ip, pkt.src_port);
        if (session == NULL) {
            //Find a session with the destination as a peer(for tracking
            //uploads from the host)
            session = findSession(pkt.dst_ip, pkt.dst_port);
            if (session == NULL)
                return;
        }

        //Make sure the destination ip matches the host
        if (pkt.dst_ip != session->getHost()) {
            //If it doesn't, and the source ip is the host, then we have an
            //upload
            if (pkt.src_ip == session->getHost()) {
                upload = true;
            }
            return;
        }

        //Make sure the peer corresponding to the source is active, or that we
        //have an upload
        Peer* source = session->getPeer(pkt.src_ip, pkt.src_port);
        if ((!(source->active)) && (upload == false)) {
            return;
        }

        //Continue a piece in flight
        if (session->getLastPiece(pkt.src_ip) != NULL) {
            if (not session->getLastPiece(pkt.src_ip)->isCompleted()) {
                //Update last piece and get any leftover data
                std::string leftover_payload;
                leftover_payload = session->getLastPiece(pkt.src_ip)->addPayload(pkt.payload);
                if (leftover_payload.size() == 0) {
                   return;
                }
                //Create a Packet to hold leftover data
                Packet leftover_pkt;
                leftover_pkt.src_ip = pkt.src_ip;
                leftover_pkt.src_port = pkt.src_port;
                leftover_pkt.dst_ip = pkt.dst_ip;
                leftover_pkt.dst_port = pkt.dst_port;
                leftover_pkt.payload = leftover_payload;
                handlePacket(leftover_pkt);

                return;
            }
        }

        //This packet should correspond to session
        //Attempt to decode it as a Piece message
        Piece *piece = new Piece(pkt.payload);
        if (not piece->isValid()) {
            return;
        }

        //Add piece to session if its not an upload
        if (!upload) {
            session->addPiece(pkt.src_ip,piece);
        }
        else {
            //All we need to record is the index of the piece.
            session->addUploadedIndex(piece->getIndex());
            delete piece;
        }
	}
}

/**
 * Gets a session associated with the given host and tracker.
 */
Session *SessionFinder::findSession(std::string host_ip, u_short host_port,
                                    std::string tracker_ip) {
    std::map<std::string, Session*>::iterator it;
    for (it = sessions.begin(); it != sessions.end(); ++it) {
        if ((it->second->getHost() == host_ip and it->second->getHostPort() == host_port)) {
            if (it->second->hasTracker(tracker_ip)) {
                return it->second;
            }
        }
    }
    return NULL;
}

/**
 * Gets a session associated with the given peer(ip:port)
 */
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
