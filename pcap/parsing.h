#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// parse and print ethernet header data
int parse_ethernet(const u_char *packet);
// parse and print ip header data
int parse_ip(const u_char *packet);
// parse and print tcp header data
int parse_tcp(const u_char *packet);
// parse and print payload data
int parse_data(const u_char *packet, bpf_u_int32 len);

#endif // PARSING_H

