#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define ADDR_ETH_LEN    6
#define ADDR_IP_LEN     4

#define IDX_PROT    9
#define PROT_TCP    0x06

#define IP_SRC_OFF  12
#define IP_DST_OFF  16

#define ASCI_CH_ST  0x20
#define ASCI_CH_ED  0x80

#define HEADER_LEN  60

// parse and print ethernet header data
int parse_ethernet(const u_char *packet);
// parse and print ip header data
int parse_ip(const u_char *packet);
// parse and print tcp header data
int parse_tcp(const u_char *packet);
// parse and print payload data
int parse_data(const u_char *packet, bpf_u_int32 len);

#endif // PARSING_H

