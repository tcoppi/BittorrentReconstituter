//#include "pcap_parser/SessionFinder.hpp"
//#include "pcap_parser/PacketHandler.hpp"
#include <fstream>
#include <iostream>
#include <streambuf>
#include <boost/program_options.hpp>

// The docs suggest this alias
namespace po = boost::program_options;

int main(int argc, char **argv) {
    std::streambuf *buffer; // Buffer to figure out which stream to use
    std::ofstream outfile; // File buffer to figure out which stream to use

    // Yay, option parsing. XD  Add any new options to desc, directly below
    po::options_description desc("BitTorrent Reconstitutor Options");
    desc.add_options()
        ("help", "Write out this help message.")
        ("output-file,o", po::value<std::string>(), 
         "Write stats and non-error messages to this file.  Defaults to stdout.")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
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
    
    output << "Testing!" << std::endl;

    // Spawn processes / pipes here and start passing them around

    return 0;
}
