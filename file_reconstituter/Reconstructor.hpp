// Take a complete session and reconstruct the files in it from the pieces.

#ifndef __RECONSTRUCTOR_H
#define __RECONSTRUCTOR_H
#include "../pcap_parser/Session.hpp"
#include <boost/archive/text_iarchive.hpp>
#include <ostream>
#include <fstream>
#include <string>

class Reconstructor {
public:
    Reconstructor(const char *input_pipe);
    void reconstructSession(Session *session);
    void run();
private:
    std::ifstream m_input;
    Session *m_curr_session;
    boost::archive::text_iarchive m_inpipe;
};

class File {
public:
    std::string name() { return this->m_name; }
    std::string data() { return this->m_data; }

    /**
     * Add a piece to the file.
     *
     * Uses the information in the piece to add it to the correct place in the
     * buffer.
     *
     * Returns true if piece was successfully added, false otherwise.
     */
    bool addPiece(Piece *piece);

    /**
     * Outputs the current contents of the buffer buffer to the file in m_name.
     */
    void writeFile(void);

private:
    std::string m_name;
    std::string m_data;
};

#endif
// vim: tabstop=4:expandtab
