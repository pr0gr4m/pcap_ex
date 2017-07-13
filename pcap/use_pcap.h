#ifndef USE_PCAP_H
#define USE_PCAP_H

// open pcap handle
int init_handle(pcap_arg *arg);
// set handle to port 80
int set_handle_port80(pcap_arg *arg);
// close pcap handle
int close_handle(pcap_arg *arg);
// capture and print packet iteratively
int print_packet_loop(pcap_arg *arg);

#endif // USE_PCAP_H

