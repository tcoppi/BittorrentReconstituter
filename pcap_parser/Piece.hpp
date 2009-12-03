// Structure to hold the data from a single BitTorrent piece message
//
// Original Author: Aaron A. Lovato

#ifndef PCAP_PARSER_PIECE_H
#define PCAP_PARSER_PIECE_H

#include <string>
#include <boost/archive/text_oarchive.hpp>
/**
 * Holds all the data from a piece message.
 */
class Piece {

public:
    Piece() {}
    Piece(std::string);
    bool isCompleted();
    bool isValid();
    std::string addPayload(std::string);
    std::string getBlock() {return this->block;}
    unsigned int getIndex() { return this->index; }
    unsigned int getOffset() { return this->offset; }

private:
    friend std::ostream & operator<<(std::ostream &, const Piece &);
    friend class boost::serialization::access;
    template<class Archive>
            void serialize(Archive & ar, const unsigned int){
        ar & index & offset & len & block & valid & complete;
            }
    //Function to convert bytes in a string to an unsigned int
    unsigned int convertUInt(std::string);

    //Whether this piece is complete
    bool complete;

    //Whether this piece is valid
    bool valid;

    //Index of the piece
    unsigned int index;

    //offset within the piece where the block starts
    unsigned int offset;

    //length of the block
    unsigned int len;

    std::string block;
};

#endif
// vim: tabstop=4:expandtab
