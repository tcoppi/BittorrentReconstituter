/**
 * Structure to contain the relevant (for this project) parts of a 
 * TCP/IP packet.
 * 
 * Note: u_short was chosen for the port numbers because that is the data
 * type that libpcap uses for port numbers.
 *
 * Original Author: Aaron A. Lovato
 */

#include <string>

typedef struct {
    std::string src_ip;
    std::string dst_ip;
    u_short src_port;
    u_short dst_port;
    std::string payload;
} Packet;