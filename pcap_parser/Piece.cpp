#include <string>
#include <iostream>
#include "Piece.hpp"
#include "SessionFinder.hpp"

/**
 * Construct a new piece object with the given payload.
 */
Piece::Piece(std::string payload) {

    //Make sure payload is long enough for decoding
    if(payload.size() < 13) {
        valid = false;
        return;
    }


    //Get length and offset into packet for fields
    int field_offset = 0;
    len = convertUInt(payload.substr(0, 4));
    if(len == 0) {
        //This is very probably a keep-alive message
        field_offset = 4;
        len = convertUInt(payload.substr(4, 4));
    }

    //Find 0x07 in 5th byte
    if(payload[4+field_offset] != PIECE) {
        valid = false;
        return;
    }

    //length is len - 9
    len = len - 9;

    //Get the index
    index = convertUInt(payload.substr(5+field_offset, 4));

    //Get the offset
    offset = convertUInt(payload.substr(9+field_offset, 4));

    if(len > 32768) {
//         std::cerr << "failing on index " << index << " and offset " << offset << std::endl;
        valid = false;
        return;
    }

    //Data is everything after the first 13 bytes
    std::string data = payload.substr(13+field_offset);

    block = std::string(data);

    if (data.size() == len) {
        //We have the whole block in this payload
        complete = true;
    }
    else {
        complete = false;
    }
    valid = true;
}

/**
 * Adds the payload from a packet to this piece's data.
 */
std::string Piece::addPayload(std::string payload) {

    //Check length of payload to see how many bytes to take
    bool has_leftover;
    unsigned int left = len - block.size();
    if (left > payload.size()) {
        //Take the whole payload
        block.append(payload);
        has_leftover = false;
    }
    else {
        //Take enough data to finish piece
        block.append(payload.substr(0, left));
        has_leftover = true;
    }


    if (block.size() == len) {
        //We have finished this piece
        complete = true;
    }
    else if (block.size() > len) {
        //This piece is invalid
        valid = false;
        complete = true;
    }
    if(has_leftover) {
        return (payload.substr(left));
    }
    else {
        return "";
    }

}

unsigned int Piece::convertUInt(std::string payload) {
    //Get length of data - WARNING! ugly-ass code follows
    std::string str_val;
    str_val = payload.substr(0, 4);
    const char * c_len = str_val.data();
    unsigned int val = ((u_char)c_len[0] << 24) | ((u_char)c_len[1] << 16) |
            ((u_char)c_len[2] << 8) | ((u_char)c_len[3]);

    return val;
}

/**
 * Returns whether this piece is complete - i.e., it has a data that matches
 * the given length.
 */
bool Piece::isCompleted() {
    return complete;
}

/**
 * Returns whether this piece is valid.
 */
bool Piece::isValid() {
    return valid;
}
