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

int parse_ip(const u_char *packet)
{
    pr_out("IP");

    pr_out_n("Source : ");
    print_ip_addr(packet + 12);
    pr_out_n("Destination : ");
    print_ip_addr(packet + 16);

    putchar('\n');
    if (packet[9] == 0x06)
        return TRUE;
    else
        return FALSE;
}

static void print_port(const u_int16_t port)
{
    printf("%d \n", port);
}

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

    if (packet[20])
        return TRUE;
    else
        return FALSE;
}

static void print_data(const u_char *data, u_int32_t len)
{
    len = len > 80 ? 80 : len;

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
        printf("%c", data[i] >= 0x20 && data[i] < 0x80 ? data[i] : '.');
    }
    putchar('\n');
}

int parse_data(const u_char *packet, bpf_u_int32 len)
{
    if (len - 54 <= 0)
        return FALSE;

    print_data(packet, len - 54);
    putchar('\n');
    return TRUE;
}
