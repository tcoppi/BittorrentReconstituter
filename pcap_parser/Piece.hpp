// Structure to hold the data from a single BitTorrent piece message
//
// Original Author: Aaron A. Lovato

#ifndef PCAP_PARSER_PIECE_H
#define PCAP_PARSER_PIECE_H

typedef struct {
    int index;
    int offset;
    const char* block;
} Piece;

#endif
