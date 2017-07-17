#include "common.h"
#include "parsing.h"

static void print_ether_addr(u_int8_t arr[])
{
    for (int i = 0; i < 6; i++)
    {
        printf("%x%c", arr[i], i == 5 ? '\n' : ':');
    }
}

/*
 * Prototype : int parse_ethernet(const u_char *packet)
 * Last modified 2017/07/12
 * Written by pr0gr4m
 *
 * parse src mac addr, dst mac addr
 * if ethernet type is ip, return TRUE
 * or return FALSE
 */
int parse_ethernet(const u_char *packet)
{
    struct ether_header *ethdr;

    ethdr = (struct ether_header *)packet;
    pr_out("Ethernet");

    pr_out_n("Source : ");
    print_ether_addr(ethdr->ether_shost);

    pr_out_n("Destination : ");
    print_ether_addr(ethdr->ether_dhost);

    putchar('\n');

    if (ntohs(ethdr->ether_type) == ETHERTYPE_IP)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static void print_ip_addr(const u_char *addr)
{
    for (int i = 0; i < 4; i++)
    {
        printf("%d%c", addr[i], i == 3 ? '\n' : '.');
    }
}

#define PROT_TCP    0x06

/*
 * Prototype : int parse_ip(const u_char *packet)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * parse src ip addr, dst ip addr
 * if protocol is TCP(0x06) return TRUE
 * or return FALSE
 */
int parse_ip(const u_char *packet)
{
    pr_out("IP");

    pr_out_n("Source : ");
    print_ip_addr(packet + 12);
    pr_out_n("Destination : ");
    print_ip_addr(packet + 16);

    putchar('\n');
    if (packet[9] == PROT_TCP)
        return TRUE;
    else
        return FALSE;
}

static void print_port(const u_int16_t port)
{
    printf("%d \n", port);
}

/*
 * Prototype : int parse_tcp(const u_char *packet)
 * Last modified 2017/07/12
 * Written by pr0gr4m
 *
 * parse src port, dst port
 * return data offset
 */
int parse_tcp(const u_char *packet)
{
    struct tcphdr *tcphdr;

    pr_out("TCP");
    tcphdr = (struct tcphdr *)packet;

    pr_out_n("Source : ");
    print_port(ntohs(tcphdr->source));
    pr_out_n("Destination : ");
    print_port(ntohs(tcphdr->dest));

    putchar('\n');

    return tcphdr->doff;
}

#define PRINT_MAX   256
#define ASCI_CH_ST  0x20
#define ASCI_CH_ED  0x80

/*
 * Prototype : static void print_data(const u_char *data, u_int32_t len)
 * Last modified 2017/07/13
 * Written by pr0gr4m
 *
 * Argument len is length of payload data.
 * if the len is over 80, cut to 80.
 * print data by hex and character
 * if hex value can't convert to character (not within from 0x20 to 0x80)
 * print '.' instead
 */
static void print_data(const u_char *data, u_int32_t len)
{
    len = len > PRINT_MAX ? PRINT_MAX : len;

    puts("Hex : ");
    for (u_int32_t i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
            putchar('\n');
    }
    putchar('\n');
    puts("Char : ");
    for (u_int32_t i = 0; i < len; i++)
    {
        printf("%c", data[i] >= ASCI_CH_ST && data[i] < ASCI_CH_ED ? data[i] : '.');
    }
    putchar('\n');
}

#define HEADER_LEN  60

/*
 * Prototype : int parse_data(const u_char *packet, bpf_u_int32 len)
 * Last modified 2017/07/13
 * Written by pr0gr4m
 *
 * Argument len is full length of packet
 * if len is over 54, print the payload data and return TRUE
 * or return FALSE
 */
int parse_data(const u_char *packet, bpf_u_int32 len)
{
    if (len <= HEADER_LEN)
        return FALSE;

    print_data(packet, len);
    putchar('\n');
    return TRUE;
}
