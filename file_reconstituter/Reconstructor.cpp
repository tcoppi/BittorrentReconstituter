#include <openssl/sha.h>

#include "Reconstructor.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"
#include "../pcap_parser/Peer.hpp"

Reconstructor::Reconstructor(const char *input, std::ofstream o)
    : m_input(input), m_inpipe(m_input) {
    this->ohandle = &o;
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
    }
}

void Reconstructor::reconstructSession(Session *s) {
    std::vector<Piece*> pieces = s->getPieces();
    File file(s->getHash()); //we need to pass along the output file name from the driver somehow
    std::map<std::string, Peer> peers = s->getPeers();
    std::map<std::string, Peer>::iterator it;

    std::vector<Piece*>::iterator p, e;
    for (p = pieces.begin(), e = pieces.end(); p != e; ++p) {
        if (not (*p)->isValid()) {
                std::cerr << "Invalid piece" << std::endl;
                return;
        }

        file.addPiece(*p);
    }

    //Output statistics
    *(this->ohandle) << "SHA-1 Info Hash: " << s->getHash() << std::endl;
    *(this->ohandle) << "Peers: " << std::endl;

    //ohandle ip:port for each peer
    for(it = peers.begin(); it == peers.end(); it++) {
        *(this->ohandle) << "\t" << (*it).second.ip << std::endl << "\t" << (*it).second.port << std::endl;
    }

    // We get file.  How are you gentlemen?  Output me to your base.
    *(this->ohandle) << "Reconstructed file size: " << file.writeFile() << std::endl;
}

File::File(std::string name) {
    this->m_name = name;
}

void File::addPiece(Piece *piece) {
    // Insert the piece's data into the correct macropiece position and offset.
    this->macropieces[piece->getIndex()].insert(piece->getOffset(), piece->getBlock());
}

unsigned int File::writeFile(void) {
    // Take every macropiece and add them all to the final buffer
    // and write it to disk
    std::ofstream outfile;
    unsigned char hash[20];

    std::map<unsigned int, std::string>::iterator s, e;

    //FIXME Here is where we should probably check the hashes of the individual
    //pieces, if we have the torrent file.
    for(s = this->macropieces.begin(), e = this->macropieces.end(); s != e; s++) {
        //compute the hash
        SHA1((const unsigned char*)(*s).second.data(), (*s).second.length(), hash);
        //TODO verify the hash. if it doesn't match, throw an error and die

        //insert the data into its correct place in the buffer
        this->m_data.insert((*s).second.length() * ((*s).first - 1), (*s).second);
    }

    //write to the file
    outfile.open(this->m_name.c_str());
    outfile << this->m_data;
    outfile.close();

    return this->m_data.length();
}

// vim: tabstop=4:expandtab
