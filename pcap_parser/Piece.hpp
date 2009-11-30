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
    Piece(std::string);
    bool isCompleted();
    bool isValid();
    void addPayload(std::string);
    
    unsigned int getIndex() { return this->index; }
    unsigned int getOffset() { return this->offset; }
    std::string getBlock() { return this->block; }

private:
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

// Boost serialization
namespace boost {
    namespace serialization {

        template<class Archive>
                void serialize(Archive & ar, Piece & p, const unsigned int version)
        {
            ar & p.index;
            ar & p.offset;
            ar & p.len;
            ar & p.block;
        }

    }
}
#endif
// vim: tabstop=4:expandtab
