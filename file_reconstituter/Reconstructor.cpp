#include "Reconstructor.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"

Reconstructor::Reconstructor(const char *ipipe)
    : input_pipe(ipipe), input(input_pipe) {
}

// for each session:
void Reconstructor::run() {
    Session sess;

    while(true) {
        try {
            input >> sess;
            reconstructSession(sess);
        }

        catch(boost::archive::archive_exception &e) {
            break;
        }
    }
}

void Reconstructor::reconstructSession(Session session) {
    std::vector<Piece*> pieces = session.getPieces();
    std::vector<Piece*>::iterator it;

    //   for each piece:
    //     check if valid
    //     use index and offset to block info
    //     Add new info to our file

    for(it = pieces.begin(); it != pieces.end(); it++) {
        if((*it)->isValid()) {

        }
    }
}


// We get file.  How are you gentlemen?
// vim: tabstop=4:expandtab
