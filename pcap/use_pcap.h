#ifndef USE_PCAP_H
#define USE_PCAP_H

int init_handle(pcap_arg *arg);
int set_handle_port80(pcap_arg *arg);
int close_handle(pcap_arg *arg);
int print_packet_loop(pcap_arg *arg);

#endif // USE_PCAP_H

