#include "send_packet.h"

libnet_ptag_t udp_tag = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t ip_tag = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t icmp_tag = LIBNET_PTAG_INITIALIZER;

u_int8_t TYPE_OF_SERVICE = 0; //Routine
u_int8_t DEFAULT_TTL = 64;

libnet_t *l;	/* libnet context */
 
int init_context_libnet() {
	char errbuf[LIBNET_ERRBUF_SIZE];
	l = libnet_init(LIBNET_RAW4, "wlan0", errbuf);
	
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		return -1;
	}
	
	return 1;
}

u_int32_t get_own_address() {
	u_int32_t ip_addr;

	ip_addr = libnet_get_ipaddr4(l);
	if ( ip_addr == -1 ) {
		printf("IP resolve address error: %s\n", libnet_addr2name4(ip_addr, LIBNET_RESOLVE));
		return -1;
	}
	
	return ip_addr;
		
}

u_int32_t convert_address(char *ip_addr_str) {
	u_int32_t ip_addr;
	
	ip_addr = libnet_name2addr4(l, ip_addr_str, LIBNET_RESOLVE);
	
	return ip_addr;
}
 
int send_data(u_int16_t sp, u_int16_t dp, u_int8_t *payload, u_int32_t payload_s, u_int32_t ip_addr) {
	int i;
	int checksum = 0;
	u_int16_t id;
	u_int8_t *ip_addr_p;
	
	printf("\tPorta de Origem: %d - ", ntohs(sp));
	printf("\tPorta Destino: %d\n", ntohs(dp));
	printf("\tTamanho do pacote a ser enviado: %d\n",  payload_s);
	
	libnet_seed_prand(l);
	id = (u_int16_t)libnet_get_prand(LIBNET_PR16);

	if ( ip_addr == -1 ) {
		fprintf(stderr, "Error converting IP address.\n");
		libnet_destroy(l);
		init_context_libnet();
		return -1;
	}

	/* Building UDP packet */
	if (libnet_build_udp(sp, dp, LIBNET_UDP_H + payload_s, 0, payload, payload_s, l, 0) == -1) {
		fprintf(stderr, "Error building UDP packet: %s\n",\
				libnet_geterror(l));
		libnet_destroy(l);
		init_context_libnet();
		return -1;
	}
	
	ip_tag = libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + payload_s, IPPROTO_UDP, ip_addr, l);

	if (ip_tag == -1) {
		fprintf(stderr, "Error building IP header: %s\n",\
				libnet_geterror(l));
		return -1;
	}

	//Ele tá dando pau aqui por causa da fragmentação
	if ( libnet_write(l) == -1 ) {
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		init_context_libnet();
		return -1;
	}
	
	return 0;

}
