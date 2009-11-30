#include "pcap_parser/SessionFinder.hpp"
#include "pcap_parser/PacketHandler.hpp"
#include <fstream>
#include <iostream>
#include <streambuf>
#include <vector>
#include <string>
#include <boost/program_options.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <pcap.h>
#include <cerrno>
#include <sys/types.h>
#include <sys/wait.h>

// The docs suggest this alias
namespace po = boost::program_options;

int main(int argc, char **argv) {
    std::streambuf *buffer; // Buffer to figure out which stream to use
    std::ofstream outfile; // File buffer to figure out which stream to use

    // Yay, option parsing. XD  Add any new options to desc, directly below
    po::options_description desc("BitTorrent Reconstitutor Options");
    desc.add_options()
        ("help,h", "Write out this help message.")
        ("output-file,o", po::value<std::string>(),
         "Write stats and non-error messages to this file.  Defaults to stdout.")
        ("input-file,i", po::value<std::vector<std::string> >(), "Input files")
        ;

    po::positional_options_description p;
    p.add("input-file", -1);

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

    // Input file stuff -- print out for debugging
    if (vm.count("input-file")) {
        output << "Input files: ";
        std::vector<std::string> v = vm["input-file"].as<std::vector<std::string> >();
        // I don't want to roll my own copy, so this leaves an extra ", " at the
        // end.  You can't delete from the end of an ostream, either,
        // apparently. XD
        copy(v.begin(), v.end(), std::ostream_iterator<std::string>(output, ", "));
    }

    // Spawn processes / pipes here and start passing them around
    while (mkfifo("intoFinder", 0744) == -1) {
        if (errno == EEXIST) {
            remove("intoFinder");
            continue;
        }
        return -1;
    }
    while (mkfifo("outofFinder", 0744) == -1) {
        if (errno == EEXIST) {
            remove("outofFinder");
            continue;
        }
        return -1;
    }

    // Fix later to allow live input -- just check if no input files
    bool live = false;
    // Just use the last name specified for now, fix later
    std::string input_name = vm["input-file"].as<std::vector<std::string> >().back();
    pcap_t* input_handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (live) {
        input_handle = pcap_open_live(input_name.c_str(), 65535, 1, 1000, errbuf);
        if (input_handle == NULL) {
            std::cerr << "Unable to open device " << input_name << ": " 
                      << errbuf << std::endl;
            return -1;
        }
    }
    else {
        input_handle = pcap_open_offline(input_name.c_str(), errbuf);
        if (input_handle == NULL) {
            std::cerr << "Unable to open file " << input_name << ": " 
                      << errbuf << std::endl;
            return -1;
        }
    }

    // Make sure the data link layer is ethernet
    if (pcap_datalink(input_handle) != DLT_EN10MB) {
        std::cerr << "Not ethernet!" << std::endl;
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        //This is the child
        output << "Starting SessionFinder" << std::endl;
        SessionFinder *sf = new SessionFinder("intoFinder", "outofFinder");
        sf->run();
    }
    else if (pid < 0) {
        std::cerr << "Someone set up us the bomb.\n";
        return -1;
    }
    else {
        //Parent 
        PacketHandler *ph = new PacketHandler(input_handle, "intoFinder");
        ph->run();
        std::cout << "waiting: " << waitpid(pid, NULL, 0) << std::endl;
        remove("intoFinder");
        remove("outofFinder");
        
    }

    return 0;
}
