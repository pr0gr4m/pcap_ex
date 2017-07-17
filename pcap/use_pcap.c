#include "common.h"
#include "use_pcap.h"
#include "parsing.h"

/*
 * Prototype : int init_handle(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * open pcap handle and store to arg
 * open argument of to_ms is 0
 */
int init_handle(pcap_arg *arg)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        pr_err("Couldn't find default device: %s\n", errbuf);
        return RET_ERR;
    }

    if (pcap_lookupnet(dev, &(arg->net), &(arg->mask), errbuf) == -1)
    {
        pr_err("Couldn't get netmask for device %s: %s\n", dev, errbuf);
        arg->net = 0;
        arg->mask = 0;
    }

    arg->handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (arg->handle == NULL)
    {
        pr_err("Couldn't open device %s: %s \n", dev, errbuf);
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int set_handle_port80(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * set filter of port 80 to handle
 */
int set_handle_port80(pcap_arg *arg)
{
    struct bpf_program fp;
    const char filter_exp[] = "port 80";

    if (pcap_compile(arg->handle, &fp, filter_exp, 0, arg->net) == -1)
    {
        pr_err("Could't parse filter %s: %s \n", filter_exp, pcap_geterr(arg->handle));
        return RET_ERR;
    }

    if (pcap_setfilter(arg->handle, &fp) == -1)
    {
        pr_err("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(arg->handle));
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int close_handle(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * close the handle
 */
int close_handle(pcap_arg *arg)
{
    pcap_close(arg->handle);
    return RET_SUC;
}

/*
 * Prototype : int print_packet_loop(pcap_arg *arg)
 * Last Modified 2017/07/13
 * Written by pr0gr4m
 *
 * capture next packets with handle iteratively
 * ethernet header default length : 14
 * ip header default length : 20
 * tcp header default length : 20
 */
int print_packet_loop(pcap_arg *arg)
{
    struct pcap_pkthdr *header;
    const u_char *packet;

    while (1)
    {
        putchar('\n');
        pcap_next_ex(arg->handle, &header, &packet);
        if (packet == NULL)
        {
            pr_err("Don't grab the packet");
        }


        pr_out("* Next Packet Length : [%d]\n", header->len);
        if (parse_ethernet(packet))
        {
            if (parse_ip(packet + HEAD_ETH_LEN))
            {
                if (parse_tcp(packet + HEAD_ETH_LEN + HEAD_IP_LEN))
                {
                    parse_data(packet + HEAD_ETH_LEN +
                               HEAD_IP_LEN + HEAD_TCP_LEN, header->len);
                }
            }
        }

        puts("======================================================================================");
    }

    return RET_SUC;
}
