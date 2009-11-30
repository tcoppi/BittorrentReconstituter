#include "Reconstructor.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"

Reconstructor::Reconstructor(const char *ipipe)
    : input_pipe(ipipe), input(input_pipe) {
}

// for each session:
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

    std::vector<Piece*>::iterator p, e;
    for (p = pieces.begin(), e = pieces.end(); p != e; ++p) {
        if (not (*p)->isValid()) { return; }

        // use index and offset to block info

        // Add new info to our file
    }

    // We get file.  How are you gentlemen?  Output me to your base.
}
// vim: tabstop=4:expandtab
