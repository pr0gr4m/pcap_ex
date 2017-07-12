#include "common.h"
#include "parsing.h"

static void print_ether_addr(u_int8_t arr[])
{
    for (int i = 0; i < 6; i++)
    {
        printf("%x%c", arr[i], i == 5 ? '\n' : ':');
    }
}

int parse_ethernet(const u_char *packet)
{
    struct ether_header *ethdr;

    ethdr = (struct ether_header *)packet;
    pr_out("Ethernet");
    pr_out_n("Destination : ");
    print_ether_addr(ethdr->ether_dhost);
    pr_out_n("Source : ");
    print_ether_addr(ethdr->ether_shost);

    return TRUE;
}

int parse_ip(const u_char *packet)
{
    return TRUE;
}

int parse_tcp(const u_char *packet)
{
    return TRUE;
}
