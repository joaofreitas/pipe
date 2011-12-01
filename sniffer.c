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

const int LOOP_SNIFF = -1;			/* Sniffer vai ficar em loop */
const int CLIENT_MODE = 0;
const int SERVER_MODE = 1;

int listen_port = 0;
int destination_port = 0;
char *host_addr;
redirect_info *redirect_data;
redirect_table *table;

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
create_package(char *ip_addr_str, u_int32_t source_port, u_int32_t destination_port, u_int8_t *payload, u_int32_t payload_size);

void
send_redirect_info(redirect_info * redirect);

/*
 * Cria pacote a ser enviado na rede, com um pseudo reader contendo informações na seguinte ordem:
 *	| ip_destino | source_port | destination_port | payload |
*/
u_int8_t *
create_package(char *ip_addr_str, u_int32_t source_port, u_int32_t destination_port, u_int8_t *payload, u_int32_t payload_size){
	u_int8_t *package;
	u_int32_t address;
	

	package = malloc(3*sizeof(u_int32_t) + payload_size);

	address = convert_address(ip_addr_str);

	memcpy(package, &address, sizeof(u_int32_t));
	memcpy(package + sizeof(u_int32_t), &source_port, sizeof(u_int32_t));
	memcpy(package + 2*sizeof(u_int32_t), &destination_port, sizeof(u_int32_t));
	memcpy(package + 3*sizeof(u_int32_t), payload, payload_size);		/*Copiando payload*/
	
	return package;
}

void print_info(int package_number, u_int32_t size_udp_package) {
	printf("\n----------- Packet number %d -----------\n", package_number);
	printf("\tTamano do pacote recebido (com header): %d\n", size_udp_package);
}

void
got_packet_client(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct libnet_ipv4_hdr *ip;				/* The IP header */
	const struct libnet_udp_hdr *udp;				/* The UDP header */
	static int count = 0;							/* packet counter */
	int size_ip;
	char *ip_addr_str;
	u_int8_t *package, *payload;
	u_int32_t ip_addr, package_size, payload_size;

	
	count++;
	ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	size_ip = IP_HL(ip)*4;

	//Convertendo endereço de destino...	
	ip_addr_str = inet_ntoa(ip->ip_dst);

	if (size_ip < 20) {
		return;
	}

	udp = (struct libnet_udp_hdr*)(packet + LIBNET_ETH_H + size_ip);
	#ifdef VERBOSE_MODE
	print_info(count, ntohs(udp->uh_ulen));
	#endif

	payload = (u_int8_t *)(packet + LIBNET_ETH_H + size_ip + LIBNET_UDP_H);
	payload_size = ntohs(udp->uh_ulen) - LIBNET_UDP_H;
	
	if (redirect_data != NULL) {		/* Significa que o usuário passou parâmetros -L e -R */
		package = create_package(redirect_data->dst_ip, ntohs(udp->uh_sport), redirect_data->dst_port, payload, payload_size);
	} else {
		package = create_package(ip_addr_str, ntohs(udp->uh_sport), ntohs(udp->uh_dport),payload, payload_size);
	}

	package_size = 3*sizeof(u_int32_t) + payload_size;
	
	ip_addr = convert_address(host_addr);
	
	//Envia pela porta padrão, por isso mandei 0
	send_data(0, destination_port, package, package_size, ip_addr);

	return;
}

void
got_packet_server(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct libnet_ipv4_hdr *ip;             		/* The IP header */
	const struct libnet_udp_hdr *wrap_udp;		/* The UDP header */
	struct in_addr src_ip;
	u_char *payload, *dst_ip_src;
	u_int32_t *ip_dst, *source_port, *destination_port, payload_s;

	static int count = 0;
	char *ip_addr_str;
	int size_ip;

	count++;
	ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	size_ip = IP_HL(ip)*4;
	
	ip_addr_str = inet_ntoa(ip->ip_dst);
	convert_address(ip_addr_str);

	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	wrap_udp = (struct libnet_udp_hdr *)(packet + LIBNET_ETH_H + size_ip);
	#ifdef VERBOSE_MODE
	print_info(count, ntohs(wrap_udp->uh_ulen));
	printf("\tPorta de Origem : %d - ", ntohs(wrap_udp->uh_sport));
	printf("\tPorta Destino: %d\n", ntohs(wrap_udp->uh_dport));
	#endif


	ip_dst = (u_int32_t *)(packet + LIBNET_ETH_H + size_ip + LIBNET_UDP_H);
	
	dst_ip_src = libnet_addr2name4(*ip_dst, LIBNET_DONT_RESOLVE);
	source_port = (u_int32_t *)(packet + LIBNET_ETH_H + size_ip + LIBNET_UDP_H + sizeof(u_int32_t));
	destination_port = (u_int32_t *)(packet + LIBNET_ETH_H + size_ip + LIBNET_UDP_H + sizeof(u_int32_t)*2);

	payload = (u_char *)(packet + LIBNET_ETH_H + size_ip + LIBNET_UDP_H + sizeof(u_int32_t)*3);
	payload_s = ntohs(wrap_udp->uh_ulen) - LIBNET_UDP_H - (sizeof(u_int32_t)*3);

	if (payload_s <= 0) {
		payload = NULL;
		payload_s = 0;
	}

	#ifdef VERBOSE_MODE
	printf("\tPorta de Origem antiga: %d - ", *source_port);
	printf("\tPorta Destino antiga: %d\n", *destination_port);
	printf("\tTamanho antigo: %u\n", payload_s);
	#endif

	/* O servidor enviará o pacote pela mesma porta que recebeu, para não ser necessário refazer o sniffer. */
	send_data(listen_port, *destination_port, payload, payload_s, *ip_dst);
	
	return;
}

void 
create_sniffer(char *dev, const ip_info *data) 
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
		redirect_data = data->constant_union.client_data->redirect;
	}

	#ifdef VERBOSE_MODE
	/* print capture info */
	printf("Device: %s\n", dev);
	#endif

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
	#ifdef VERBOSE_MODE
	printf("Filtro: %s\n", filter_exp);
	#endif

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
	
	if (init_context_libnet(dev) == -1) {
		exit(EXIT_FAILURE);
	}
	
	pcap_loop(handle, LOOP_SNIFF, callback_func, NULL);
	
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

}

