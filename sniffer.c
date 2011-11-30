#include "sniffer.h"

/************************
DEFINES
************************/

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define IP_HL(ip)               (((ip)->ip_v << 4 | (ip)->ip_hl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/************************
GLOBAIS
************************/

int LOOP_SNIFF = -1;			/* Sniffer vai ficar em loop */
int listen_port = 0;
int destination_port = 0;
char *host_addr;

int CLIENT_MODE = 0;
int SERVER_MODE = 1;

/************************
FUNCÕES
************************/

void
got_packet_server(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
got_packet_client(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_info(int package_number, u_int32_t size_udp_package);

u_int8_t *
create_package(struct in_addr ip_addr, u_int8_t *payload, u_int32_t payload_size);

u_int8_t *
create_package(struct in_addr ip_addr, u_int8_t *payload, u_int32_t payload_size){
	u_int8_t *package;
	u_int32_t address;
	char *ip_addr_str;

	package = malloc(sizeof(u_int32_t) + payload_size);

	//Convertendo endereço...	
	ip_addr_str = inet_ntoa(ip_addr);
	address = convert_address(ip_addr_str);

	memcpy(package, &address, sizeof(u_int32_t));
	memcpy(package, payload, payload_size);
	
	return package;
}

void print_info(int package_number, u_int32_t size_udp_package) {
	printf("\n----------- Packet number %d -----------\n", package_number);
	printf("\tTamano do pacote recebido: %d\n", size_udp_package);
}

void
got_packet_client(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct libnet_ipv4_hdr *ip;              /* The IP header */
	const struct libnet_udp_hdr *udp;		/* The UDP header */
	static int count = 0;                   /* packet counter */
	int size_ip;
	u_int8_t *package, *payload;
	u_int32_t ip_addr, package_size, payload_size;
	
	count++;
	ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	size_ip = IP_HL(ip)*4;

	if (size_ip < 20) {
		return;
	}

	udp = (struct libnet_udp_hdr*)(packet + LIBNET_ETH_H + size_ip);
	print_info(count, ntohs(udp->uh_ulen));

	payload = (u_int8_t *)(packet + LIBNET_ETH_H + size_ip); // Todos dados do UDP, inclusive com o cabeçalho.
	payload_size = ntohs(udp->uh_ulen) - LIBNET_UDP_H;

	package = create_package(ip->ip_src, payload, payload_size);
	package_size = sizeof(u_int32_t) + payload_size;
	
	ip_addr = convert_address(host_addr);
	//Envia de uma porta padrão, por isso mandei 0
	send_data(0, destination_port, package, package_size, ip_addr);
	free(package);

	return;
}

void
got_packet_server(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct libnet_ipv4_hdr *ip;              /* The IP header */
	const struct libnet_udp_hdr *wrap_udp, *udp;		/* The UDP header */
	package_info *package;
	u_char *payload;
	u_int8_t *ip_addr_p;					//Isso é para fins de teste

	static int count = 0;
	int size_ip;

	count++;
	ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	size_ip = IP_HL(ip)*4;

	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	wrap_udp = (struct libnet_udp_hdr *)(packet + LIBNET_ETH_H + size_ip);
	print_info(count, ntohs(wrap_udp->uh_ulen));
	printf("\tPorta de Origem : %d - ", ntohs(wrap_udp->uh_sport));
	printf("\tPorta Destino: %d\n", ntohs(wrap_udp->uh_dport));

	package = (package_info *)(packet + LIBNET_ETH_H + size_ip + LIBNET_UDP_H);
	udp = (struct libnet_udp_hdr *)(package->payload); // Pacote UDP dentro de outro UDP
	printf("\tPorta de Origem antiga: %d - ", ntohs(udp->uh_sport));
	printf("\tPorta Destino antiga: %d\n", ntohs(udp->uh_dport));
	printf("\tTamanho antigo: %d\n", ntohs(udp->uh_ulen));

	ip_addr_p = (u_int8_t*)(&package->dst_ip_addr);
/*
	printf("\tPorta de Origem - Wrap: %d - ", ntohs(wrap_udp->uh_sport));
	printf("\tPorta Destino- Wrap: %d\n", ntohs(wrap_udp->uh_dport));
	printf("\tPorta de Origem: %d - ", ntohs(udp->uh_sport));
	printf("\tPorta Destino: %d\n", ntohs(udp->uh_dport));*/
	printf("\tEndereço: %d.%d.%d.%d\n", ip_addr_p[0], ip_addr_p[1], ip_addr_p[2], ip_addr_p[3]);
//	printf("\tTamanho do pacote: %d\n", ntohs(udp->uh_ulen));
	
//	payload = (package_info *)(packet + LIBNET_ETH_H + size_ip + 2*LIBNET_UDP_H);
//	send_data(udp->uh_sport, payload, ntohs(udp->uh_ulen), ip_addr);
	
	/*

	//Deveria reenviar o pacote
	*/
	

	return;
}

void 
create_sniffer(const char *dev, const ip_info *data) 
{
	pcap_t *handle;								/* packet capture handle */
	bpf_u_int32 mask;							/* subnet mask */
	bpf_u_int32 net;							/* ip */
	struct bpf_program fp;						/* compiled filter program (expression) */
	
	void *callback_func;
	char errbuf[PCAP_ERRBUF_SIZE];				/* error buffer */
	char buffer[] = "udp dst port";				/* filter expression [3] */
	char filter_exp[30];

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
	
	if (data->tag == SERVER_MODE) {
		listen_port = data->constant_union.server_data->s_port;
		callback_func = &got_packet_server;
	} else {
		host_addr = data->constant_union.client_data->ip_addr;
		listen_port = data->constant_union.client_data->s_port;
		destination_port = data->constant_union.client_data->d_port;
		callback_func = &got_packet_client;
	}

	/* print capture info */
	printf("Device: %s\n", dev);

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
	
	/* Assembling new filter expression */
	sprintf (filter_exp, "%s %d", buffer, listen_port);
	printf("Filtro: %s\n", filter_exp);

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
	
	
	if (init_context_libnet() == -1) {
		exit(EXIT_FAILURE);
	}
	
	pcap_loop(handle, LOOP_SNIFF, callback_func, NULL);
	
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

}

