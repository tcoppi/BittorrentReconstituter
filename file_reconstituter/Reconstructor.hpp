// Take a complete session and reconstruct the files in it from the pieces.

#ifndef __RECONSTRUCTOR_H
#define __RECONSTRUCTOR_H
#include "../pcap_parser/Session.hpp"
#include <boost/archive/text_iarchive.hpp>
#include <ostream>
#include <fstream>
#include <string>
typedef std::map<std::string, std::vector<std::string> > hash_map_t;

class Reconstructor {
public:
    Reconstructor(const char *input_pipe, std::ofstream o, hash_map_t hashes);
    void reconstructSession(Session *session);
    void run();
private:
    std::ifstream m_input;
    Session *m_curr_session;
    boost::archive::text_iarchive m_inpipe;
    std::ofstream *ohandle;
    hash_map_t piece_hashes;
};

class File {
public:
    File(std::string);
    std::string name() { return this->m_name; }
    std::string data() { return this->m_data; }

    /**
     * Add a piece to the file.
     *
     * Uses the information in the piece to add it to the correct place in the
     * buffer.
     */
    void addPiece(Piece *);

    /**
     * Outputs the current contents of the buffer buffer to the file.
     *
     * Returns the number of bytes written.
     */
    unsigned int writeFile(void);

private:
    std::string m_name;
    std::string m_data;

    /**
     * Map of all the large pieces, indexed by the piece's index.
     */
    std::map<unsigned int, std::string> macropieces;
};

#endif
// vim: tabstop=4:expandtab
