#include "Torrent.hpp"
#include <fstream>
#include <openssl/sha.h>
#include <stdlib.h>
#include <iostream>

Torrent::Torrent(std::string file) : filename(file) {}

bool Torrent::init() {
    std::ifstream in_file(filename.c_str());
    std::string data;
    char current;

    //Read all data from file;
    while (in_file.good()) {
        current = in_file.get();

        if (in_file.good())
            data.push_back(current);
    }

    // Find info dictionary
    size_t offset = data.find("4:info") + 6;
    std::string info_dict = data.substr(offset);

    //Get end of info dictionary
    size_t announce_off = data.find("8:announce");
    if (announce_off == std::string::npos) {
        return false;
    }
    if (announce_off > offset) {
        this->announce_url = info_dict.substr(0, announce_off);
    }

    //Strip the info dictionary of extra fields
    this->stripExtraFields(info_dict);
    std::cout << "info dict: " << info_dict << std::endl;

    // etc, etc
    //Get the info hash
    const unsigned char* raw_info_dict = (const unsigned char*) info_dict.data();
    unsigned char raw_info_hash[20];
    SHA1(raw_info_dict, info_dict.size(), raw_info_hash);
    this->m_info_hash = std::string((const char*) raw_info_hash, 20);

    //Get length and number of pieces
    size_t pieces_off = info_dict.find("6:pieces") + 8;
    size_t endoff = info_dict.find(":", pieces_off);
    size_t pieces_len = (int) atoi(info_dict.substr(pieces_off, endoff-pieces_off).c_str());

    //Get the pieces string
    std::string pieces = info_dict.substr(endoff+1, pieces_len);

    //Get the piece hashes themselves
    m_num_pieces = pieces_len / 20;
    for(size_t i = 0; i < m_num_pieces; i++) {
        //Add to map
        this->m_piece_hashes.push_back(pieces.substr(i*20, 20));
    }

    // Decode the info dictionary to get the file information
    // For now, only care about multi file mode
    size_t files_off = info_dict.find("5:files");
    if(files_off != std::string::npos) {
        //We have multiple files
        files_off += 7;
        std::string files_dict = info_dict.substr(files_off);
        this->stripInfo(files_dict);
        std::cout << "files: " << files_dict << std::endl;
    }

    in_file.close();
    return true;
}

/**
 * Strip the given field of any extra fields. Use stripInfo to string fields
 * from the info dictionary.
 */

void Torrent::stripExtraFields(std::string &field) {

    if(field.find("8:url-list") != std::string::npos) {
        field = field.substr(0, field.find("8:url-list"));
    }
    if(field.find("13:creation date") != std::string::npos) {
        field = field.substr(0, field.find("13:creation date"));
    }
    if(field.find("7:comment") != std::string::npos) {
        field = field.substr(0, field.find("7:comment"));
    }
    if(field.find("10:created by") != std::string::npos) {
        field = field.substr(0, field.find("10:created by"));
    }
    if(field.find("8:encoding") != std::string::npos) {
        field = field.substr(0, field.find("8:encoding"));
    }

    //These two are added by mininova
    if(field.find("6:locale") != std::string::npos) {
        field = field.substr(0, field.find("6:locale"));
    }
    if(field.find("5:title") != std::string::npos) {
        field = field.substr(0, field.find("5:title"));
    }
}

void Torrent::stripInfo(std::string &field) {

    if(field.find("12:piece length") != std::string::npos) {
        field = field.substr(0, field.find("12:piece length"));
    }
    if(field.find("6:pieces") != std::string::npos) {
        field = field.substr(0, field.find("6:pieces"));
    }
    if(field.find("7:private") != std::string::npos) {
        field = field.substr(0, field.find("7:private"));
    }
}
