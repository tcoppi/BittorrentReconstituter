/**
 * This class represents a module that parses a pcap file and identifies
 * BitTorrent sessions.
 *
 * Original Author: Aaron A. Lovato
 */
#ifndef PCAP_PARSER_SESSION_FINDER_H
#define PCAP_PARSER_SESSION_FINDER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <stdbool.h>
#include <arpa/inet.h>

/* States of the session finder */
#define START 0
#define HAVE_TRACKER_REQUEST 1
#define HAVE_TRACKER_RESPONSE 2

/* IDs of the bittorrent messages we care about */
#define CHOKE 0
#define UNCHOKE 1
#define INTERESTED 2
#define NINTERESTED 3
#define HAVE 4
#define REQUEST 6
#define PIECE 7

// XXX We should maybe do this dynamically, in which case this needs to be a
// const static int, and we'll have to do some const_casting to fix c++'s const
// correctness.  Or we'll have to create the Peer object differently to stop the
// compiler complaining, since we initialize an array with this number.
// Whichever is fine with me.
#define MAX_PEERS 1024

typedef struct {
    std::string ip; // required

    // It might be easier to just store this as an int, since thats the format we get
    // it in most of the time
    unsigned int ipi;

    u_short port; // required
    std::string peer_id; // optional, urlencoded
    unsigned int left; // optional, number of bytes left for client to download

    // true if we got this peer info from a tracker request, false if from a
    // tracker response
    bool isreq;
} Peer;

class SessionFinder {
public:
    void Init(); // Use this instead of the constructor

private:
    SessionFinder(std::string, bool);
    void handlePacket(const u_char *packet, const struct pcap_pkthdr *header);

    /* These both return a index into the peers array */
    unsigned int findPeerIP(unsigned int ip);
    u_short findPeerPort(u_short port);

    /* This uniquely identifies the torrent(file) that is being downloaded.
       If we see other requests with different info hashes, they are
       different transfers. */
    std::string info_hash; /*url and bencoded, shouldn't matter since we don't
                            *need* the raw value, just the fact that it is unique. */
    Peer peers[MAX_PEERS];
    std::string input_name;
    pcap_t *input_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bool live;
    unsigned int state;
    unsigned int peer_index;
    unsigned int num_seeders;
};

#endif
