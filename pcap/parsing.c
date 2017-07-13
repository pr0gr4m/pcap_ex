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
    return TRUE;
}

static void print_data(const u_char *data)
{
    for (int i = 0; i < 40; i++)
    {
        printf("%c", data[i] >= 0x20 && data[i] < 0x80 ? data[i] : '.');
    }
    putchar('\n');
}

int parse_data(const u_char *packet)
{
    puts("======================================== Data ========================================");
    print_data(packet);
    puts("======================================================================================");
    putchar('\n');
    return TRUE;
}
