#include "send_packet.h"

/**
 * Builds an RFC 768 User Datagram Protocol (UDP) header.
 * @param sp source port
 * @param dp destination port
 * @param len total length of the UDP packet
 * @param payload optional payload or NULL
 * @param payload_s payload length or 0
 * @param ip_addr_str ip of host
 * @return protocol tag value on success, -1 on error
 */
int send_data(u_int16_t sp, u_int16_t dp, u_int16_t packet_len, u_int8_t *payload, u_int32_t payload_s, char *ip_addr_str) {

	char errbuf[LIBNET_ERRBUF_SIZE];
	int i;
	libnet_t *l;	/* libnet context */
	u_int32_t ip_addr;
	u_int16_t id, seq;

	l = libnet_init(LIBNET_RAW4, "wlan0", errbuf);
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		return -1;
	}

	libnet_seed_prand(l);
	id = (u_int16_t)libnet_get_prand(LIBNET_PR16);

	ip_addr = libnet_name2addr4(l, ip_addr_str, LIBNET_RESOLVE);

	if ( ip_addr == -1 ) {
		fprintf(stderr, "Error converting IP address.\n");
		libnet_destroy(l);
		return -1;
	}

	/* Building ICMP header */
	if (libnet_build_udp(sp, dp, packet_len, 0, payload, payload_s, l, 0) == -1) {
		fprintf(stderr, "Error building UDP packet: %s\n",\
				libnet_geterror(l));
		libnet_destroy(l);
		return -1;
	}
	seq = 1;

	/* Building IP header */
	if (libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + packet_len, IPPROTO_UDP, ip_addr, l) == -1) {
		fprintf(stderr, "Error building IP header: %s\n",\
				libnet_geterror(l));
		libnet_destroy(l);
		return -1;
	}

	if ( libnet_write(l) == -1 ) {
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
		return -1;
	}

	return 0;

}
