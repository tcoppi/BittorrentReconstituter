#include <string>
#include <iostream>
#include "Piece.hpp"
#include "SessionFinder.hpp"

/**
 * Piece constructor - performs packet parsing magic.
 */
Piece::Piece(std::string payload) {

    //Make sure payload is long enough for decoding
    if(payload.size() < 13) {
        valid = false;
        return;
    }

    //Find 0x07 in 5th byte
    if(payload[4] != PIECE) {
        valid = false;
        return;
    }

    //Get length
    len = convertUInt(payload.substr(0, 4));
    //length is len - 9
    len = len - 9;

    //Get the index
    index = convertUInt(payload.substr(5, 4));

    //Get the offset
    offset = convertUInt(payload.substr(9, 4));

    //Data is everything after the first 13 bytes
    std::string data = payload.substr(13);

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
 * Adds the payload given to this piece's block.
 */
void Piece::addPayload(std::string payload) {
    block.append(payload);
    if (block.size() == len) {
        //We have finished this piece
        complete = true;
    }
    else if (block.size() > len) {
        //This piece is invalid
        valid = false;
    }
}

/**
 * Takes the first 4 bytes from payload and returns the unsigned int
 * equivalent.
 */
unsigned int Piece::convertUInt(std::string payload) {
    std::cout << "converting payload: " << payload << std::endl;
    //Get length of data - WARNING! ugly-ass code follows
    std::string str_val;
    str_val = payload.substr(0, 4);
    const char * c_len = str_val.data();
    unsigned int val = 0;
    val = (val << 8) + c_len[0];
    val = (val << 8) + c_len[1];
    val = (val << 8) + c_len[2];
    val = (val << 8) + c_len[3];

    return val;
}


/**
 * Returns whether this piece is completed.
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
