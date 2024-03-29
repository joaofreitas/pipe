#include "send_packet.h"

libnet_ptag_t udp_tag = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t ip_tag = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t icmp_tag = LIBNET_PTAG_INITIALIZER;

char *dev;
u_int8_t TYPE_OF_SERVICE = 0; //Routine
u_int8_t DEFAULT_TTL = 64;
u_int16_t DEFAULT_SOURCE_PORT = 20000;

libnet_t *l;	/* libnet context */
 
int init_context_libnet(char *device) {
	dev = device;
	
	return 1;
}

u_int32_t convert_address(char *ip_addr_str) {
	u_int32_t ip_addr;
	
	ip_addr = libnet_name2addr4(l, ip_addr_str, LIBNET_RESOLVE);

	return ip_addr;
}
 
int send_data(u_int16_t source_port, u_int16_t destination_port, u_char *payload, u_int32_t payload_s, u_int32_t ip_addr) {
	int i;
	int checksum = 0;
	char errbuf[LIBNET_ERRBUF_SIZE];
	u_int16_t id;
	u_int8_t *ip_addr_p;
	
	l = libnet_init(LIBNET_RAW4, dev, errbuf);
	
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		return -1;
	}

	if (source_port == 0) {
		source_port = DEFAULT_SOURCE_PORT;
	}
	
	ip_addr_p = (u_int8_t *)(&ip_addr);
	#ifdef VERBOSE_MODE
	printf("\tPorta de Origem: %d - ", source_port);
	printf("\tPorta Destino: %d\n", destination_port);
	printf("\tTamanho do pacote a ser enviado (sem header): %d\n",  payload_s);
	printf("\tVou reenviar para: %d.%d.%d.%d\n", ip_addr_p[0], ip_addr_p[1], ip_addr_p[2], ip_addr_p[3]);
	#endif
	libnet_seed_prand(l);
	id = (u_int16_t)libnet_get_prand(LIBNET_PR16);

	if ( ip_addr == -1 ) {
		fprintf(stderr, "Error converting IP address.\n");
		return -1;
	}
	
	/* Building UDP packet */
	if (libnet_build_udp(source_port, destination_port, LIBNET_UDP_H + payload_s, 0, payload, payload_s, l, 0) == -1) {
		fprintf(stderr, "Error building UDP packet: %s\n",\
				libnet_geterror(l));
		return -1;
	}
	
	if (libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + payload_s, IPPROTO_UDP, ip_addr, l) == -1) {
		fprintf(stderr, "Error building IP header: %s\n",\
				libnet_geterror(l));
		return -1;
	}
	

	if (libnet_write(l) == -1 ) {
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
		return -1;
	}
	
	libnet_destroy(l);
	
	return 0;

}
