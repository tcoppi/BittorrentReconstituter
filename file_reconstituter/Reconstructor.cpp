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

void File::addPiece(Piece *piece) {
    // Insert the piece's data into the correct macropiece position and offset.
    this->macropieces[piece->getIndex()].insert(piece->getOffset(), piece->getBlock());
}

void File::writeFile(void) {
    // Take every macropiece and add them all to the final buffer
    // and write it to disk

    std::map<unsigned int, std::string>::iterator s, e;

    for(s = this->macropieces.begin(), e = this->macropieces.end(); s != e; s++) {
        this->m_data.insert((*s).second.length() * ((*s).first - 1), (*s).second);
    }
}

// vim: tabstop=4:expandtab
