/* Take a complete session and reconstruct the files in it from the pieces that
 * have been gathered by SessionFinder.
 */
#ifndef __RECONSTRUCTOR_H
#define __RECONSTRUCTOR_H
#include "../pcap_parser/Session.hpp"
#include "Torrent.hpp"
#include <boost/archive/text_iarchive.hpp>
#include <ostream>
#include <fstream>
#include <string>
typedef std::map<std::string, std::vector<std::string> > hash_map_t;

class Reconstructor {
public:
    Reconstructor(const char *input_pipe, std::ofstream &o,
                  std::vector<Torrent*> torrents);

    /**
     * Main reconstruction function, outputs statistics, matches any torrent
     * files to the session, and uses the File class to reconstruct the file(s)
     * in the session.
     */
    void reconstructSession(Session *session);
    void run();
private:
    std::ifstream m_input;
    Session *m_curr_session;
    boost::archive::text_iarchive m_inpipe;
    std::ofstream *ohandle;
    std::vector<Torrent*> m_torrents;
};

class File {
public:
    File() {}
    File(std::string);
    std::string name() { return this->m_name; }
    void name(std::string x) { this->m_name = x;}
    std::string contents() { return this->m_contents; }

    /**
     * Add a piece to the file.
     *
     * Uses the information in the piece to add it to the correct place in the
     * buffer.
     */
    void addPiece(Piece *);

    /**
     * Reconstructs the file(s) and verifies the SHA-1 hashes of the pieces, if
     * the torrent file is available.
     */
    void reconstructFile(Torrent*);

    /**
     * Outputs the current contents of the buffer buffer to the file.
     *
     * Returns the number of bytes written.
     */
    unsigned int writeFile(unsigned int begin, unsigned int length);

private:
    std::string m_name;
    std::string m_contents;

    /**
     * Map of all the large pieces, indexed by the piece's index.
     */
    std::map<unsigned int, std::string> macropieces;
};

#endif
// vim: tabstop=4:expandtab
