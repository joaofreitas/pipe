#include <stdio.h>
#include <pcap.h>
#include "send_packet.c"

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
