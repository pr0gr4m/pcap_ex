#include "common.h"
#include "use_pcap.h"

int main(int argc, char *argv[])
{
    pcap_arg arg;

    if (init_handle(&arg))
    {
        exit(EXIT_FAILURE);
    }

    if (set_handle_port80(&arg))
    {
        exit(EXIT_FAILURE);
    }

    if (print_packet_loop(&arg))
    {
        exit(EXIT_FAILURE);
    }

    if (close_handle(&arg))
    {
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
