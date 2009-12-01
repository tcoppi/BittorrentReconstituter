#include "pcap_parser/SessionFinder.hpp"
#include "pcap_parser/PacketHandler.hpp"
#include "file_reconstituter/Reconstructor.hpp"
#include <boost/exception/get_error_info.hpp>
#include <boost/program_options.hpp>
#include <cassert>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <pcap.h>
#include <streambuf>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <openssl/sha.h>
typedef std::map<std::string, std::vector<std::string> > hash_map_t;

// Does the work of spawning processes and running pipes between them
void handle_pcap_file(pcap_t *input_handle, int i, 
                      hash_map_t hashes, std::ofstream &output) {
    std::string in_pipe_str("intoFinder" + i);
    const char *in_pipe = in_pipe_str.c_str();
    std::string out_pipe_str("outofFinder" + i);
    const char *out_pipe = out_pipe_str.c_str();

    // Make sure the data link layer is ethernet
    if (pcap_datalink(input_handle) != DLT_EN10MB) {
        std::cerr << "Not ethernet!" << std::endl;
        return;
    }

    // If the pipe already exists just remove it and try to make again
    while (mkfifo(in_pipe, 0744) == -1) {
        if (errno == EEXIST) {
            remove(in_pipe);
            continue;
        }
        return;
    }
    while (mkfifo(out_pipe, 0744) == -1) {
        if (errno == EEXIST) {
            remove(out_pipe);
            continue;
        }
        return;
    }

    // Warning: What follows is some relatively nasty process action
    pid_t pid = fork();
    if (pid == 0) {
        //This is the child
        SessionFinder *sf = new SessionFinder(in_pipe, out_pipe);
        sf->run();
    }
    else if (pid < 0) {
        std::cerr << "Someone set up us the bomb.\n";
        return;
    }
    else {
        //Parent 
        pid_t newpid = fork();
        if (newpid == 0) {
            Reconstructor *recon = new Reconstructor(out_pipe, output, hashes);
            recon->run();
        }
        else if (pid < 0) {
            std::cerr << "You have no chance to survive, make your time.\n";
            return;
        }
        else {
            PacketHandler *ph = new PacketHandler(input_handle, in_pipe);
            ph->run();
            waitpid(newpid, NULL, 0);
            waitpid(pid, NULL, 0);
            remove(in_pipe);
            remove(out_pipe);
        }
    }
    return;
}


// The docs suggest this alias
namespace po = boost::program_options;

int main(int argc, char **argv) {
    bool live = false; // False unless an interface is given
    pcap_t* input_handle;
    std::ofstream outfile; // File buffer to figure out which stream to use
    std::streambuf *buffer; // Buffer to figure out which stream to use
    std::string interface_name;
    std::vector<std::string> pcap_files;
    std::vector<std::string> torrent_files;
    hash_map_t hashes; // Map of info hashes to list of piece hashes

    // Yay, option parsing. XD  Add any new options to desc, directly below
    po::options_description desc("BitTorrent Reconstitutor Options");
    desc.add_options()
        ("help,h", "Write out this help message.")
        ("output-file,o", po::value<std::string>(),
         "Write stats and non-error messages to this file.  Defaults to stdout.")
        ("input-file,r", po::value<std::vector<std::string> >(), "Pcap / Torrent files")
        ("interface,i", po::value<std::string>(), "Specify interface for live processing")
        ;

    po::positional_options_description p;
    p.add("input-file", -1);

    try { // Don't change the indentation level here because it spans the rest of the function
    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 1; // We're not really using return codes, so yeah.
    }

    // Change our output to a file if specified.  This code is not exception
    // safe as it stands.
    if (vm.count("output-file")) {
        // Sorry for the extra ugly here.  C++ can't figure out its own
        // references, nor can it construct/open a file from it's own string
        // type, you must use a c string.  Thanks, C++ language designers.
        outfile.open(vm["output-file"].as<std::string>().c_str());
        buffer = outfile.rdbuf();
    }
    else {
        buffer = std::cout.rdbuf();
    }
    // Finally construct the correct output stream
    std::ostream output(buffer);

    // interface and input-file are mutually exclusive options
    if (vm.count("interface")) {
        live = true;
        interface_name = vm["interface"].as<std::string>();
    }
    else if (vm.count("input-file")) {
        // Input file stuff, parse out the pcap and torrent vectors and figure
        // out if we're going live
        std::vector<std::string> v = vm["input-file"].as<std::vector<std::string> >();

        std::vector<std::string>::iterator i, e;
        for (i = v.begin(), e = v.end(); i != e; ++i) {
            if ((*i).substr((*i).size()-5, (*i).size()) == ".pcap") {
                pcap_files.push_back(*i);
            }
            else if((*i).substr( (*i).size()-8, (*i).size()) == ".torrent") {
                torrent_files.push_back(*i);
            }
        }
        // Keep this for debugging purposes:
        // Leaves an extra ", " at the end, but you can't delete from ostreams, so oh well
        //     output << "Input files: ";
        //     copy(v.begin(), v.end(), std::ostream_iterator<std::string>(output, ", "));
    }
    else {
        // We have no input of any sort, toss out the help message
        std::cout << desc << std::endl;
        return 1;
    }
    
    //Create map of hashes
    std::vector<std::string>::iterator torrent_file;
    for (torrent_file = torrent_files.begin(); 
         torrent_file != torrent_files.end(); ++torrent_file) {

        std::string data;
        char current;
    
        //Open input file
        std::ifstream input_file((*torrent_file).c_str());
        
        //Read all data from file;
        while (input_file.good()) {
            current = input_file.get();
            if (input_file.good()) {
                data.push_back(current);
            }

        }
        
        //Find info dictionary
        size_t offset = data.find("4:info") + 6;
        std::string info_dict = data.substr(offset);
    
        //Get end of info dictionary
        size_t announce_off = data.find("8:announce");
        if(announce_off == std::string::npos) {
            //Invalid torrent file
            continue;
        }
        if(announce_off > offset) {
            info_dict = info_dict.substr(0, announce_off);
        }
        
        //Find the first if any field after the info dictionary
        if(info_dict.find("8:url-list") != std::string::npos) {
            info_dict = info_dict.substr(0, info_dict.find("8:url-list"));
        }
        if(info_dict.find("13:creation date") != std::string::npos) {
            info_dict = info_dict.substr(0, info_dict.find("13:creation date"));
        }
        if(info_dict.find("7:comment") != std::string::npos) {
            info_dict = info_dict.substr(0, info_dict.find("7:comment"));
        }
        if(info_dict.find("10:created by") != std::string::npos) {
            info_dict = info_dict.substr(0, info_dict.find("10:created by"));
        }
        if(info_dict.find("8:encoding") != std::string::npos) {
            info_dict = info_dict.substr(0, info_dict.find("8:encoding"));
        }
        
        //Get the info hash
        const unsigned char* raw_info_dict = (const unsigned char*) info_dict.data();
        unsigned char raw_info_hash[20];
        SHA1(raw_info_dict, info_dict.size(), raw_info_hash);
        std::string info_hash = std::string((const char*) raw_info_hash, 20);
        
        //Get length of pieces
        size_t pieces_off = info_dict.find("6:pieces") + 8;
        size_t endoff = info_dict.find(":", pieces_off);
        size_t pieces_len = (int) atoi(info_dict.substr(pieces_off, endoff-pieces_off).c_str());

        //Get the pieces string
        std::string pieces = info_dict.substr(endoff+1, pieces_len);

        //Get the piece hashes themselves
        size_t num_pieces = pieces_len / 20;
        for(size_t i = 0; i < num_pieces; i++) {
            //Add to map
            hashes[info_hash].push_back(pieces.substr(i*20, 20));
        }
    }

    // Just use the last name specified for now, fix later
    char errbuf[PCAP_ERRBUF_SIZE];
    if (live) {
        // Automatically detect the routing interface
        // with: netstat -nr | grep -e 'default|0.0.0.0' | awk '{ print $NF; }'
        // ^ We don't need that, use the -i option instead
        input_handle = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
        if (input_handle == NULL) {
            std::cerr << "Unable to open device " << interface_name << ": " 
                      << errbuf << std::endl;
            return -1;
        }
        handle_pcap_file(input_handle, 0, hashes, outfile);
    }
    else {
        std::vector<std::string>::iterator i, e;
        int num;
        for (i = pcap_files.begin(), e = pcap_files.end(), num = 0; i != e; ++i, ++num) {
            std::string input_name = *i;

            input_handle = pcap_open_offline(input_name.c_str(), errbuf); 
            if (input_handle == NULL) {
                std::cerr << "Unable to open file " << input_name << ": " 
                          << errbuf << std::endl;
                return -1;
            }
            handle_pcap_file(input_handle, num, hashes, outfile);
        }
    }
    } // end intentional malformed indentation
    catch (const char *c) {
        std::cerr << "Error: " << c << std::endl;
        return -1;
    }
    catch (boost::exception& e) { // If we have a failed arg parse
        //        std::cerr << "Error: " << boost::get_error_info(e) << std::endl;
        // Just error out generically for now, I guess.  The boost exception stuff is acting up
        std::cerr << "Error with arg parsing" << std::endl; 
        return -1;
    }
    catch (...) { // Something bad happened -- we should have caught this
        assert(0 && "Failing badly.");
    }
    
    return 0;
}

