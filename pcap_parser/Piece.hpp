// Structure to hold the data from a single BitTorrent piece message
//
// Original Author: Aaron A. Lovato

#ifndef PCAP_PARSER_PIECE_H
#define PCAP_PARSER_PIECE_H

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

#endif
// vim: tabstop=4:expandtab
