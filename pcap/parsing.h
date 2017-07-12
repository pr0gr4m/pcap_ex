#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int parse_ethernet(const u_char *packet);
int parse_ip(const u_char *packet);
int parse_tcp(const u_char *packet);

#endif // PARSING_H

