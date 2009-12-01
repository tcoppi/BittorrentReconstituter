#include <openssl/sha.h>
#include "Reconstructor.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"
#include "../pcap_parser/Peer.hpp"
typedef std::map<std::string, std::vector<std::string> > hash_map_t;

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
    std::vector<Piece*> pieces = s->getPieces();
    File file(s->getHash()); //we need to pass along the output file name from the driver somehow
    std::map<std::string, Peer> peers = s->getPeers();
    std::map<std::string, Peer>::iterator it;

//    std::cout.rdbuf((*(this->ohandle)).rdbuf());

    std::vector<Piece*>::iterator p, e;
    for (p = pieces.begin(), e = pieces.end(); p != e; ++p) {
        if (not (*p)->isValid()) {
                std::cerr << "Invalid piece" << std::endl;
                return;
        }

        file.addPiece(*p);
    }

    //Output statistics
    std::cout << "SHA-1 Info Hash: " << std::endl << "\t";
    const char *h = s->getHash().data();
    for (int i = 0; i < 20; i++)
            printf("%x", (unsigned char)h[i]);
    std::cout << std::endl;

    std::cout << "Peers: " << std::endl;

    //output ip:port for each peer
    for (it = peers.begin(); it != peers.end(); it++) {
        std::cout << "\t" << (*it).second.ip << ":" << (*it).second.port << std::endl;
    }

    // We get file.  How are you gentlemen?  Output me to your base.
    std::cout << "Reconstructed file size: " << file.writeFile(this->piece_hashes) << " bytes." << std::endl;
}

File::File(std::string name) {
    this->m_name = name;
}

void File::addPiece(Piece *piece) {
    // Insert the piece's data into the correct macropiece position and offset.
    this->macropieces[piece->getIndex()].insert(piece->getOffset(), piece->getBlock());
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

unsigned int File::writeFile(hash_map_t hashes){
    // Take every macropiece and add them all to the final buffer
    // and write it to disk
    std::ofstream outfile;
    unsigned char hash[20];

    std::map<unsigned int, std::string>::iterator s, e;

    int index = 0;

    //FIXME Here is where we should probably check the hashes of the individual
    //pieces, if we have the torrent file.
    for (s = this->macropieces.begin(), e = this->macropieces.end(); s != e; s++) {
        //compute the hash
        SHA1((const unsigned char*)(*s).second.data(), (*s).second.length(), hash);
        //Verify the hash. if it doesn't match, throw an error and die
        if (hashes.find(this->m_name) == hashes.end())
            std::cout << "No torrent file specified, not verifying piece hashes." << std::endl;
        else {
            std::cout << "Found a torrent file with the same SHA-1 Info hash, verifying the piece(s) SHA-1(s)" << std::endl;
            if (not compare_sha1s((unsigned char *)hashes[this->m_name][index].data(), hash)) {
                throw "Invalid SHA-1 hash for piece";
            }

            std::cout << "SHA-1(s) verified successfully!" << std::endl;
        }
        this->m_data.insert(index, s->second);
        index += s->second.size();

        //insert the data into its correct place in the buffer


//         this->m_data.insert((*s).second.length() * ((*s).first - 1), (*s).second);
    }

    //write to the file
//     outfile.open(this->m_name.c_str());
    std::cout << this->m_data;
//     outfile.close();

    return this->m_data.length();
}

// vim: tabstop=4:expandtab
