#include "Reconstructor.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"

Reconstructor::Reconstructor(const char *input)
    : m_input(input), m_inpipe(m_input) {
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
        if (not (*p)->isValid()) {
                std::cerr << "Invalid piece" << std::endl;
                return;
        }

        // use index and offset to block info

        // Add new info to our file
    }

    // We get file.  How are you gentlemen?  Output me to your base.
}

bool Reconstructor::addPiece(Piece *piece) {
    //we need a way to get the length of a whole piece.
    //one way to do this may be to hold off adding pieces to the data until we
    //have all the individual blocks of one piece index and add its length
    //together. Assuming 32kb for now, since that is the block size of all our
    //test torrents
    unsigned int length_of_piece = 32768;
    this->m_data.insert((piece->getIndex() * length_of_piece) + piece->getOffset(), piece->getBlock());

    return true;
}
// vim: tabstop=4:expandtab
