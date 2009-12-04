#include <openssl/sha.h>
#include "Reconstructor.hpp"
#include "Torrent.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"
#include "../pcap_parser/Peer.hpp"
typedef std::map<std::string, std::vector<std::string> > hash_map_t;
typedef std::map<std::string, std::vector<Piece*> > ip_piece_map_t;

Reconstructor::Reconstructor(const char *input, std::ofstream &o,
                             std::vector<Torrent*> torrents)
    : m_input(input), m_inpipe(m_input), ohandle(&o), m_torrents(torrents) {
}

void Reconstructor::run() {
    Session s;
    while (true) {
        try {
            std::cout << "waiting for a session to reconstruct" << std::endl;
            this->m_inpipe >> s;
            std::cout << "got a session to reconstruct" << std::endl;

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
    // We get one monolithic file from a session.  If we have the torrent file
    // we can break it up, otherwise the user will have to do it manually, as we
    // don't have that information.
    File file;

    ip_piece_map_t pieces = s->getPieces();
    std::map<std::string, Peer> peers = s->getPeers();
    std::map<std::string, Peer>::iterator it;
    char hash_string[42];
    unsigned char temp_hash[20];
//    std::cout.rdbuf((*(this->ohandle)).rdbuf());

    // Output statistics
    std::cout << "SHA-1 Info Hash: " << std::endl << "\t";
    const char *h = s->getHash().data();
    for (int i = 0; i < 20; i++)
        printf("%x", (unsigned char)h[i]);
    std::cout << std::endl;

    // Build up our file from the session pieces
    ip_piece_map_t::iterator m, me;
    std::vector<Piece*>::iterator p, pe;
    for (m = pieces.begin(), me = pieces.end(); m != me; ++m) {
        for (p = m->second.begin(), pe = m->second.end(); p != pe; ++p) {
            if (not (*p)->isValid()) {
                assert(0 && "Should never have an invalid piece here");
            }
            file.addPiece(*p);
        }
    }

    std::cout << "Peers: " << std::endl;
    //output ip:port for each peer
    for (it = peers.begin(); it != peers.end(); it++) {
        std::cout << "\t" << it->second.ip << ":"
                  << it->second.port << std::endl;
    }

    // Do possible file breakup here if we have the torrent

    file.reconstructFile(this->m_torrents, s->getHash().data());

    // Name the file after its checksum
    const unsigned char *data = (const unsigned char*) file.contents().data();
    SHA1(data, file.contents().length(), temp_hash);
    //FIXME This is disgusting
    snprintf(hash_string, 42, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
             (unsigned char)temp_hash[0], (unsigned char)temp_hash[1],
             (unsigned char)temp_hash[2], (unsigned char)temp_hash[3],
             (unsigned char)temp_hash[4], (unsigned char)temp_hash[5],
             (unsigned char)temp_hash[6], (unsigned char)temp_hash[7],
             (unsigned char)temp_hash[8], (unsigned char)temp_hash[9],
             (unsigned char)temp_hash[10], (unsigned char)temp_hash[11],
             (unsigned char)temp_hash[12], (unsigned char)temp_hash[13],
             (unsigned char)temp_hash[14], (unsigned char)temp_hash[15],
             (unsigned char)temp_hash[16], (unsigned char)temp_hash[17],
             (unsigned char)temp_hash[18], (unsigned char)temp_hash[19]);
    file.name(hash_string);

    std::cout << "Output filename: " << hash_string << std::endl;

    // We get file.  How are you gentlemen?  Output me to your base.
    std::cout << "Reconstructed file size: "
              << file.writeFile()
              << " bytes." << std::endl;
}

// File::File(std::string name) : m_name(name) {}

void File::addPiece(Piece *piece) {
    // Insert the piece's data into the correct macropiece position and offset.

    // We can't assume the pieces are in order so we have to check if we need
    // to allocate space in the string
    unsigned int offset = piece->getOffset();
    if(offset >= this->macropieces[piece->getIndex()].size()) {
        this->macropieces[piece->getIndex()].resize(offset, ' ');
        this->macropieces[piece->getIndex()].insert(piece->getOffset(), piece->getBlock());
    }

//     std::cerr << "index: " << piece->getIndex() << " offset: " << piece->getOffset();
    this->macropieces[piece->getIndex()].replace(piece->getOffset(),
                                      piece->getBlock().size(), piece->getBlock());
}

/**
 * Compare the two SHA-1 hashes byte for byte and return true if they are the
 * same, false otherwise.
 */
bool compare_sha1s(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < 20; i++) {
       if (a[i] != b[i]) return false;
    }
    return true;
}

void File::reconstructFile(std::vector<Torrent*> torrents, const char *raw_info_hash) {
    // Take every macropiece and add them all to the final buffer
    unsigned char hash[20];
    bool havetorrent = false;
    Torrent *torrent = NULL; // hold torrent for this file if found

    std::vector<Torrent*>::iterator i, ie;
    for (i = torrents.begin(), ie = torrents.end(); i != ie; ++i) {
        if ((*i)->info_hash() == raw_info_hash) {
            havetorrent = true;
            torrent = *i;
            // UI Point - Test if we can singularize this string (piece's SHA1)
            std::cout << "Found a torrent file with the same SHA-1 info hash,"
                      << " verifying the pieces' SHA-1s" << std::endl;
        }
    }

    if (not havetorrent)
        std::cout << "No matching torrent file found, not verifying piece hashes." << std::endl;

    unsigned int index = 0;
    std::map<unsigned int, std::string>::iterator s, se;
    for (s = this->macropieces.begin(), se = this->macropieces.end(); s != se; ++s) {
        // Compute the hash
        SHA1((const unsigned char*)s->second.data(), s->second.length(), hash);

        // Verify the hash. if it doesn't match, throw an error and die
        std::cerr << "Checking piece number " << s->first << ".  Has hash ";
        for (int i=0; i < 20; i++)
            fprintf(stderr, "%x", (u_char)(torrent->piece_hashes().at(s->first).data())[i]);
        std::cerr << std::endl << "Expecting hash ";
        for (int i=0; i < 20; i++)
            fprintf(stderr, "%x", (u_char)hash[i]);
        std::cerr << std::endl;

        if (havetorrent and
            (not compare_sha1s((u_char *)torrent->piece_hashes().at(s->first).data(), hash))) {
            std::cout << "error" << std::endl;
            throw "Invalid SHA-1 hash for piece";
        }

        if (havetorrent)
            std::cout << "SHA-1 verified successfully for piece " << s->first << std::endl;

        std::cout << "Added piece " << s->first << std::endl;

        //insert the data into its correct place in the buffer
        this->m_contents.insert(index, s->second);
        index += s->second.size();
    }

}

unsigned int File::writeFile(void) {
    std::ofstream outfile;

    //write to the file
     outfile.open(this->m_name.c_str());
//    std::cout << this->m_contents;
     outfile << this->m_contents;
     outfile.close();

    return this->m_contents.length();
}

// vim: tabstop=4:expandtab
