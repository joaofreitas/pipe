#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/************************
DEFINES
************************/
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define IP_HL(ip)               (((ip)->ip_v << 4 | (ip)->ip_hl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/************************
CONSTANTES
************************/

int LOOP_SNIFF = -1;			/* Sniffer vai ficar em loop */
int listen_port = 0;

/************************
FUNCÕES
************************/

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_udp_header(const struct libnet_udp_hdr *udp);

/*
 * imprime o cabeçalho udp e retorna o seu tamanho.
 */
void
print_udp_header(const struct libnet_udp_hdr *udp)
{
	printf("\t\tSrc port: %d\n", ntohs(udp->uh_sport));
	printf("\t\tDst port: %d\n", ntohs(udp->uh_dport));
	printf("\t\tSize udp packet: %d\n", ntohs(udp->uh_ulen));
	
}

void print_info(int count, const struct libnet_ipv4_hdr *ip, int size_ip) {
	printf("----------- Protocol: UDP -----------\n");
	printf("Packet number %d:\n", count);
	printf("Size ip: %d\n", size_ip);
	
	/* print source and destination IP addresses */
	printf("\tFrom: %s\n", inet_ntoa(ip->ip_src));
	printf("\tTo: %s\n", inet_ntoa(ip->ip_dst));
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct libnet_ipv4_hdr *ip;              /* The IP header */
	const struct libnet_udp_hdr *udp;		/* The UDP header */
	
	static int count = 1;                   /* packet counter */
	int size_ip;
	int size_transport_layer = 0;
	
	count++;

	ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	size_ip = IP_HL(ip)*4;

	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	if (ip->ip_p == IPPROTO_UDP) {
		/* determine protocol */	
		if (ip->ip_p == IPPROTO_UDP) {
			udp = (struct libnet_udp_hdr*)(packet + LIBNET_ETH_H + size_ip);
			
			if (ntohs(udp->uh_sport) == listen_port) {
				print_info(count, ip, size_ip);
				print_udp_header(udp);
			}
		
		}
	}

	return;
}

void 
create_sniffer(const char *dev, int s_port) 
{
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	listen_port = s_port;
	if (dev == NULL) {

		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", LOOP_SNIFF);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, LOOP_SNIFF, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

}

