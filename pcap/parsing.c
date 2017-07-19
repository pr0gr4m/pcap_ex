#include "parsing.h"

static void print_ether_addr(u_int8_t addr[])
{
    for (int i = 0; i < ADDR_ETH_LEN; i++)
    {
        printf("%02x%c", addr[i], i == 5 ? '\n' : ':');
    }
}

/*
 * Prototype : int parse_ethernet(const u_char *frame)
 * Last modified 2017/07/18
 * Written by pr0gr4m
 *
 * parse src mac addr, dst mac addr
 * if ethernet type is ip, return TRUE
 * or return FALSE
 */
int parse_ethernet(const u_char *frame)
{
    struct ether_header *ethdr;

    ethdr = (struct ether_header *)frame;
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

static void print_ip_addr(const struct in_addr addr)
{
    char buf[BUF_LEN];
    inet_ntop(AF_INET, (const void *)&addr, buf, BUF_LEN);

    if (buf == NULL)
        return;

    puts(buf);
}

/*
 * Prototype : int parse_ip(const u_char *packet, int *tot_len, int *ip_hlen)
 * Last Modified 2017/07/18
 * Written by pr0gr4m
 *
 * parse src ip addr, dst ip addr
 * if protocol is TCP(0x06) return TRUE
 * or return FALSE
 */
int parse_ip(const u_char *packet, int *tot_len, int *ip_hlen)
{
    struct ip *iphdr = (struct ip *)packet;

    pr_out("IP");

    pr_out_n("Source : ");
    print_ip_addr(iphdr->ip_src);
    pr_out_n("Destination : ");
    print_ip_addr(iphdr->ip_dst);

    *tot_len = ntohs(iphdr->ip_len);
    *ip_hlen = iphdr->ip_hl;

    putchar('\n');
    if (packet[IDX_PROT] == IPPROTO_TCP)
        return TRUE;
    else
        return FALSE;
}

static void print_port(const u_int16_t port)
{
    printf("%d \n", port);
}

/*
 * Prototype : int parse_tcp(const u_char *segment, int *tcp_doff)
 * Last modified 2017/07/18
 * Written by pr0gr4m
 *
 * parse src port, dst port
 * return data offset
 */
int parse_tcp(const u_char *segment, int *tcp_doff)
{
    struct tcphdr *tcphdr = (struct tcphdr *)segment;

    pr_out("TCP");

    pr_out_n("Source : ");
    print_port(ntohs(tcphdr->source));
    pr_out_n("Destination : ");
    print_port(ntohs(tcphdr->dest));

    putchar('\n');

    *tcp_doff = tcphdr->doff;

    return tcphdr->doff;
}

#define PRINT_MAX   256

/*
 * Prototype : static void print_data(const u_char *data, u_int32_t len)
 * Last modified 2017/07/18
 * Written by pr0gr4m
 *
 * Argument len is length of payload data.
 * if the len is over PRINT_MAX, cut to PRINT_MAX.
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

/*
 * Prototype : int parse_data(const u_char *payload, bpf_u_int32 len)
 * Last modified 2017/07/18
 * Written by pr0gr4m
 *
 * Argument len is full length of packet
 * if len is over 54, print the payload data and return TRUE
 * or return FALSE
 */
int parse_data(const u_char *payload, bpf_u_int32 len)
{
    print_data(payload, len);
    putchar('\n');
    return TRUE;
}
