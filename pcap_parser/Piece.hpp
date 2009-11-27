// Structure to hold the data from a single BitTorrent piece message
//
// Original Author: Aaron A. Lovato

#ifndef PCAP_PARSER_PIECE_H
#define PCAP_PARSER_PIECE_H

#include <boost/archive/text_oarchive.hpp>
/**
 * Holds all the data from a piece message.
 */
typedef struct {
    //Index of the peice
    unsigned int index;

    //offset within the piece where the block starts
    unsigned int offset;

    //length of the block
    unsigned int len;

   char *block;
} Piece;

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
