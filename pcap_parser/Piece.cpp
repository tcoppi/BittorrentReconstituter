#include <string>
#include <iostream>
#include "Piece.hpp"
#include "SessionFinder.hpp"

Piece::Piece(std::string payload) {

    //Make sure payload is long enough for decoding
    if(payload.size() < 13) {
        valid = false;
        return;
    }

//     std::cerr << "printing payload: " << std::endl;
//     fprintf(stderr, "%02x", (u_char) payload.at(0));
//     fprintf(stderr, "%02x", (u_char) payload.at(1));
//     fprintf(stderr, "%02x", (u_char) payload.at(2));
//     fprintf(stderr, "%02x", (u_char)payload.at(3));
//     fprintf(stderr, "%02x\n", (u_char)payload.at(4));


    //Get length and offset into packet for fields
    int field_offset = 0;
    len = convertUInt(payload.substr(0, 4));
//     std::cerr << "len : " << len << std::endl;
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
//     std::cerr << "printing offset: " << std::endl;
//     fprintf(stderr, "%02x", (u_char) payload.at(9));
//     fprintf(stderr, "%02x", (u_char) payload.at(10));
//     fprintf(stderr, "%02x", (u_char) payload.at(11));
//     fprintf(stderr, "%02x\n", (u_char)payload.at(12));


    offset = convertUInt(payload.substr(9+field_offset, 4));

    if(len > 32768) {
//         std::cerr << "failing on index " << index << " and offset " << offset << std::endl;
        valid = false;
        return;
    }

    //Data is everything after the first 13 bytes
    std::string data = payload.substr(13+field_offset);
//     std::cerr << "got a valid packet" << std::endl;
//     std::cerr << "index: " << index << std::endl;
//     std::cerr << "offset: " << offset << std::endl;
//     std::cerr << "len: " << len << std::endl;

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
//         std::cerr << "completed piece" << std::endl;
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


bool Piece::isCompleted() {
    return complete;
}

bool Piece::isValid() {
    return valid;
}
