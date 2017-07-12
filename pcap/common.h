#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define TURE    1
#define FALSE   0

#define RET_SUC 0
#define RET_ERR 2

typedef struct _pcap_arg
{
    pcap_t *handle;
    bpf_u_int32 mask;
    bpf_u_int32 net;
} pcap_arg;

#define print_msg(io, msgtype, arg...) \
    flockfile(io); \
    fprintf(io, "["#msgtype"] [%s/%s:%03d] ", __FILE__, __FUNCTION__, __LINE__); \
    fprintf(io, arg); \
    fputc('\n', io); \
    funlockfile(io)

#define pr_err(arg...) print_msg(stderr, ERR, arg)
#define pr_out(arg...) print_msg(stdout, REP, arg)

#endif // COMMON_H

