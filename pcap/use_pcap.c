#include "use_pcap.h"

/*
 * Prototype : int init_handle(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * open pcap handle and store to arg
 * open argument of to_ms is 0
 */
int init_handle(pcap_arg *arg, char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL)
    {
        pr_err("Couldn't find default device: %s\n", errbuf);
        return RET_ERR;
    }

    /*
    if (pcap_lookupnet(dev, &(arg->net), &(arg->mask), errbuf) == -1)
    {
        pr_err("Couldn't get netmask for device %s: %s\n", "dum0", errbuf);
        arg->net = 0;
        arg->mask = 0;
    }
    */

    arg->net = 0;
    arg->mask = 0;

    arg->handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (arg->handle == NULL)
    {
        pr_err("Couldn't open device %s: %s \n", "dum0", errbuf);
        return RET_ERR;
    }

    return RET_SUC;
}

static int set_handle_port(pcap_arg *arg, char arr[])
{
    struct bpf_program fp;
    char filter_exp[BUF_LEN];

    snprintf(filter_exp, BUF_LEN, "%s %s", "port", arr);

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
 * Prototype : int set_handle_port80(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * set filter of port 80 to handle
 */
int set_handle_port80(pcap_arg *arg)
{

    if (set_handle_port(arg, "80") == RET_ERR)
    {
        return RET_ERR;
    }
    else
    {
        return RET_SUC;
    }
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
 * Last Modified 2017/07/18
 * Written by pr0gr4m
 *
 * capture next packets with handle iteratively
 * ethernet header default length : 14
 * ip header default length : hl * 4
 * tcp header default length : doff * 4
 */
int print_packet_loop(pcap_arg *arg)
{
    struct pcap_pkthdr *header;
    const u_char *frame, *packet, *segment, *payload;
    int ret_next;
    int tot_len, ip_hlen, tcp_doff;

    while (1)
    {
        putchar('\n');
        ret_next = pcap_next_ex(arg->handle, &header, &frame);

        if (ret_next == 0)
            continue;

        if (ret_next != 1)
            break;

        if (frame == NULL)
        {
            pr_err("Don't grab the packet");
        }

        pr_out("* Next Packet Length : [%d]\n", header->len);
        if (parse_ethernet(frame))
        {
            packet = frame + HEAD_ETH_LEN;
            if (parse_ip(packet, &tot_len, &ip_hlen))
            {
                segment = packet + ip_hlen * 4;
                if (parse_tcp(segment, &tcp_doff))
                {
                    if (tot_len + HEAD_ETH_LEN > 60 &&
                            tot_len > ip_hlen * 4 + tcp_doff * 4)
                    {
                        // pass a packet which has no payload data.
                        payload = segment + tcp_doff * 4;
                        parse_data(payload, tot_len -
                                   (ip_hlen * 4 + tcp_doff * 4));

                    }
                }
            }
        }

        puts("======================================================================================");
    }

    return RET_SUC;
}
