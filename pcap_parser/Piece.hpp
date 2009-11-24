// Structure to hold the data from a single BitTorrent piece message
//
// Original Author: Aaron A. Lovato

#ifndef PCAP_PARSER_PIECE_H
#define PCAP_PARSER_PIECE_H

typedef struct {
    unsigned int index; //Index of the peice
    unsigned int offset; //offset within the piece where the block starts
    unsigned int len; //length of the block
    const char *block;
} Piece;

#endif
