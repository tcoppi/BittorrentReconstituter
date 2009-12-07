#include <openssl/sha.h>
#include "Reconstructor.hpp"
#include "Torrent.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"
#include "../pcap_parser/Peer.hpp"
typedef std::map<std::string, std::vector<std::string> > hash_map_t;
typedef std::map<std::string, std::vector<Piece*> > ip_piece_map_t;

/**
 * Compare the two SHA-1 hashes byte for byte and return true if they are the
 * same, false otherwise.
 */
static bool compare_sha1s(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < 20; i++) {
       if (a[i] != b[i]) return false;
    }
    return true;
}

static void print_sha1(FILE *fd, const unsigned char *a) {
    for (int i=0; i < 20; i++)
            fprintf(fd, "%x", (unsigned char)a[i]);
}


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
    Torrent *torrent = NULL; // Hold the torrent for this session if we have it

    ip_piece_map_t pieces = s->getPieces();
    std::map<std::string, Peer> peers = s->getPeers();
    std::map<std::string, Peer>::iterator it;
    std::vector<unsigned int>::iterator uit;
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

    //output upload statistics(if any)
    for (uit = s->getUploadedIndices().begin();
                    uit != s->getUploadedIndices().end(); uit++) {
            std::cout << "Uploaded part of piece index " << *uit << std::endl;
    }

    std::vector<Torrent*>::iterator i, ie;
    for (i = this->m_torrents.begin(), ie = this->m_torrents.end(); i != ie; ++i) {
//        if ((*i)->info_hash() == s->getHash().data()) {
        if (compare_sha1s((const unsigned char *)(*i)->info_hash().data(),
                          (const unsigned char *)s->getHash().data())) {
            torrent = *i;
        }
    }
    file.reconstructFile(torrent);

    if (torrent == NULL) {
        // We still want to output, just no verification.  Refactor this ASAP
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
                  << file.writeFile(0, std::string::npos)
                  << " bytes." << std::endl;
        return;
    }

    // Break up files here
    unsigned int file_offset = 0;
    std::vector<unsigned int> v = torrent->file_lengths();
    for (unsigned int i=0; i < v.size(); ++i) {
        std::cerr << "i: " << i << " file_offset: " << file_offset << "\n";
        std::cerr << "v.at(i): " << v.at(i) << std::endl;

        std::string curr_file = file.contents().substr(file_offset, v.at(i));
        // Name the file after its checksum
        const unsigned char *data = (const unsigned char*) curr_file.data();
        SHA1(data, curr_file.length(), temp_hash);
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
                  << file.writeFile(file_offset, v.at(i))
                  << " bytes." << std::endl;

        file_offset += v.at(i);
    }
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

void File::reconstructFile(Torrent *torrent) {
    // Take every macropiece and add them all to the final buffer
    unsigned char hash[20];
    bool havetorrent = false;
    if (torrent != NULL) havetorrent = true;

    if (not havetorrent)
        std::cout << "No matching torrent file found, not verifying piece hashes." << std::endl;

    unsigned int index = 0;
    std::map<unsigned int, std::string>::iterator s, se;
    for (s = this->macropieces.begin(), se = this->macropieces.end(); s != se; ++s) {
        // Compute the hash
        SHA1((const unsigned char*)s->second.data(), s->second.length(), hash);

        // DEBUG
        if (havetorrent) {
            std::cerr << "Checking piece number " << s->first << ".  Has hash ";
            print_sha1(stderr, (const unsigned char *)
                            (torrent->piece_hashes().at(s->first).data()));
            std::cerr << std::endl << "Expecting hash ";
            print_sha1(stderr, (const unsigned char *)hash);
            std::cerr << std::endl;
        }

        // Verify the hash. if it doesn't match, throw an error and die
        if (havetorrent and
            (not compare_sha1s((u_char *)torrent->piece_hashes().at(s->first).data(), hash))) {
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

unsigned int File::writeFile(unsigned int begin, unsigned int length) {
    std::ofstream outfile;

    outfile.open(this->m_name.c_str());
    outfile << this->m_contents.substr(begin, length);
    outfile.close();

    return this->m_contents.length();
}

// vim: tabstop=4:expandtab
