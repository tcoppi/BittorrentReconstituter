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
    Reconstructor(const char *input_pipe, std::ostream &output);
    void run();
   
private:
    Session *curr_session;
    boost::archive::text_iarchive input;
};

class File {
public:
    std::string name() { return this->m_name; }
    std::string data() { return this->m_data; }
private:
    std::string m_name;
    std::string m_data;
};

#endif
