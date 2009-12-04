#ifndef __TORRENT_H
#define __TORRENT_H
#include <vector>
#include <map>
#include <string>
typedef std::vector<std::pair<int, std::string> > mult_mode_file_t;

class Torrent {
public:
    Torrent(std::string file);
    bool init(); // Parse the torrent file
    std::string info_hash() { return this->m_info_hash; }
    std::vector<std::string> piece_hashes() { return this->m_piece_hashes; }
    size_t num_pieces() { return this->m_num_pieces; }
    std::vector<int> file_lengths() { return this->m_file_lengths; }
    
private:
    void stripExtraFields(std::string&);
    void stripInfo(std::string&);

    //The length of the files, in sequential order
    std::vector<int> m_file_lengths;
    
    std::string filename;
    //std::map<> info;
    std::string announce_url;

    // Common to all modes
    int piece_length;
    std::vector<std::string> m_piece_hashes;
    std::string m_info_hash;
    size_t m_num_pieces;

    // Mode specific attributes
    bool single_mode;
    std::string sing_mode_name;
    std::string mult_mode_dir;
    mult_mode_file_t files;
};

#endif
