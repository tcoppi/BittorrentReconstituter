#ifndef __TORRENT_H
#define __TORRENT_H
#include <vector>
#include <string>
typedef std::vector<std::pair<int, std::string> > mult_mode_t;

class Torrent {
public:
    Torrent(std::string file);
    void init(); // Parse the torrent file

private:
    std::string filename;
    //    std::map<> info;
    std::string announce_url;

    // Common to all modes
    int piece_length;
    std::vector<std::string> piece_hashes;

    // Mode specific attributes
    bool single_mode;
    std::string sing_mode_name;
    std::string mult_mode_dir;
    mult_mode_t files;
};

#endif
