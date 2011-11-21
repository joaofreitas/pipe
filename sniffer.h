#include <stdio.h>
#include <pcap.h>

typedef struct client_data_structure {
	int s_port;
} client_structure;

typedef struct server_data_structure {
	int s_port;
	char *ip_addr;
} server_structure;

typedef struct ip_structure {
	unsigned char tag;
	union {
		client_structure *client_data;
		server_structure *server_data;
	} constant_union;
} ip_info;

void
create_sniffer(const char *dev, const ip_info *data);
