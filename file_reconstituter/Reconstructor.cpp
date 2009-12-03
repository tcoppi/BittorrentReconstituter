#include <openssl/sha.h>
#include "Reconstructor.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"
#include "../pcap_parser/Peer.hpp"
typedef std::map<std::string, std::vector<std::string> > hash_map_t;
typedef std::map<std::string,std::vector<Piece*> > ip_piece_map_t;


Reconstructor::Reconstructor(const char *input, std::ofstream &o, hash_map_t phashes)
    : m_input(input), m_inpipe(m_input) {
    this->ohandle = &o;
    this->piece_hashes = phashes;
}

void Reconstructor::run() {
    Session s;
    while (true) {
        try {
            this->m_inpipe >> s;
            this->reconstructSession(&s);
        }
        catch (boost::archive::archive_exception &e) {
            break;
        }
        catch (std::length_error &e) {
            //XXX TODO FIXME
            //Should fix length error here instead of catching
            break;
        }
    }
}

void Reconstructor::reconstructSession(Session *s) {
    ip_piece_map_t pieces = s->getPieces();
    std::map<std::string, Peer> peers = s->getPeers();
    std::map<std::string, Peer>::iterator it;
    char hash_string[42];

//    std::cout.rdbuf((*(this->ohandle)).rdbuf());

    //Output statistics
    std::cout << "SHA-1 Info Hash: " << std::endl << "\t";
    const char *h = s->getHash().data();
    for (int i = 0; i < 20; i++) {
            printf("%x", (unsigned char)h[i]);
    }
    std::cout << std::endl;

    //XXX FIXME this is disgusting
    snprintf(hash_string, 42, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
                    (unsigned char)h[0], (unsigned char)h[1],
                    (unsigned char)h[2], (unsigned char)h[3],
                    (unsigned char)h[4], (unsigned char)h[5],
                    (unsigned char)h[6], (unsigned char)h[7],
                    (unsigned char)h[8], (unsigned char)h[9],
                    (unsigned char)h[10], (unsigned char)h[11],
                    (unsigned char)h[12], (unsigned char)h[13],
                    (unsigned char)h[14], (unsigned char)h[15],
                    (unsigned char)h[16], (unsigned char)h[17],
                    (unsigned char)h[18], (unsigned char)h[19]);
    File file(hash_string);

    ip_piece_map_t::iterator m, me;
    std::vector<Piece*>::iterator p, pe;
    for (m = pieces.begin(), me = pieces.end(); m != me; ++m) {
        for (p = (*m).second.begin(), pe = (*m).second.end(); p != pe; ++p) {
            if (not (*p)->isValid()) {
                std::cerr << "Invalid piece" << std::endl;
                // return;
            }
            file.addPiece(*p);
        }
    }

    std::cout << "Peers: " << std::endl;
    //output ip:port for each peer
    for (it = peers.begin(); it != peers.end(); it++) {
        std::cout << "\t" << (*it).second.ip << ":"
                  << (*it).second.port << std::endl;
    }

    // We get file.  How are you gentlemen?  Output me to your base.
    std::cout << "Reconstructed file size: "
              << file.writeFile(this->piece_hashes, s->getHash().data())
              << " bytes." << std::endl;
}

File::File(std::string name) {
    this->m_name = name;
}

void File::addPiece(Piece *piece) {
    // Insert the piece's data into the correct macropiece position and offset.

    // We can't assume the pieces are in order so we have to check if we need
    // to allocate space in the string
    unsigned int offset = piece->getOffset();
    if(offset >= this->macropieces[piece->getIndex()].size()) {
        this->macropieces[piece->getIndex()].resize(offset, ' ');
    }

//     std::cerr << "index: " << piece->getIndex() << " offset: " << piece->getOffset();
    this->macropieces[piece->getIndex()].insert(piece->getOffset(), piece->getBlock());
//     std::cerr << " fuck" << std::endl;

}

/**
 * Compare the two SHA-1 hashes byte-byte byte and return true if they are the
 * same, false otherwise.
 */
bool compare_sha1s(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < 20; i++) {
       if (a[i] != b[i]) return false;
    }
    return true;
}

unsigned int File::writeFile(hash_map_t hashes, const char *raw_info_hash){
    // Take every macropiece and add them all to the final buffer
    // and write it to disk
    std::ofstream outfile;
    unsigned char hash[20];
    bool havetorrent = false;

    std::map<unsigned int, std::string>::iterator s, e;

    if (hashes.find(raw_info_hash) == hashes.end()) {
        std::cout << "No torrent file specified, not verifying piece hashes." << std::endl;
    }
    else {
            havetorrent = 1;
            std::cout << "Found a torrent file with the same SHA-1 Info hash, verifying the piece(s) SHA-1(s)" << std::endl;
    }

    unsigned int index = 0;
    for (s = this->macropieces.begin(), e = this->macropieces.end(); s != e; s++) {
        //compute the hash
        SHA1((const unsigned char*)(*s).second.data(), (*s).second.length(), hash);

        //Verify the hash. if it doesn't match, throw an error and die
        if (havetorrent and (not compare_sha1s((unsigned char *)hashes[raw_info_hash][(*s).first].data(), hash))) {
            std::cout << "error" << std::endl;
            throw "Invalid SHA-1 hash for piece";
        }

        if (havetorrent)
            std::cout << "SHA-1 verified successfully for piece " << s->first << std::endl;

        std::cout << "Added piece " << (*s).first << std::endl;

        //insert the data into its correct place in the buffer
        this->m_data.insert(index, s->second);
        index += s->second.size();
    }

    //write to the file
     outfile.open(this->m_name.c_str());
//    std::cout << this->m_data;
     outfile << this->m_data;
     outfile.close();

    return this->m_data.length();
}

// vim: tabstop=4:expandtab
