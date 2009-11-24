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
#include <stdbool>
#include <arpa/inet.h>

/* States of the session finder */
static int START = 0;
static int HAVE_TRACKER_REQUEST = 1;
static int HAVE_TRACKER_RESPONSE = 2;

/* IDs of the bittorrent messages we might care about */
static int CHOKE = 0;
static int UNCHOKE = 1;
static int INTERESTED = 2;
static int NINTERESTED = 3;
static int HAVE = 4;
static int REQUEST = 6;
static int PIECE = 7;

static int MAX_PEERS = 1024; //XXX should do this dynamically
static int MAX_PIECES = 2056;

typedef struct {
    std::string ip; // requiredi
    unsigned int ipi; // might be easier to just store it as an int, since thats the format we get it in most of the time
    u_short port; // required

    std::string peer_id; //optional, urlencoded
    unsigned int left; //optional, number of bytes left for client to download
    bool isreq; //true if we got this peer info from a tracker request, false if from a tracker response
} Peer;

//this doesn't belong here
typedef struct {
    unsigned int piece_index; //major piece index
    unsigned int offset; //offset within major piece
    unsigned int len; //number of bytes of data
    char *data;
} Piece;

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
       If we see other tracker requests with different info hashes, they are
       different transfers.
     */
    std::string info_hash; /*url and bencoded, need to de-urlencode it so we
			     can compare it to peers and identify a session. */
    Peer peers[MAX_PEERS]; //maybe make this a linked list?
    Piece pieces[MAX_PIECES]; //XXX i think we want this as a vector
    std::string input_name;
    pcap_t* input_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bool live;
    unsigned int state;
    unsigned int peer_index;
    unsigned int num_seeders;
};

#endif
