#include "Reconstructor.hpp"
#include "../pcap_parser/Session.hpp"
#include "../pcap_parser/Piece.hpp"

Reconstructor::Reconstructor(const char *input)
    : m_input(input), m_curr_session(), m_inpipe(m_input) {}

void Reconstructor::run() {
    // for each session:
    //   for each piece:
    //     check if valid
    //     use index and offset to block info
    //     Add new info to our file

    // We get file.  How are you gentlemen?
}
