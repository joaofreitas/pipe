#ifndef __STRUCTURES_H
#define __STRUCTURES_H

#include <stdio.h>

typedef struct client_data_structure {
	int s_port;
	char *ip_addr;
} client_structure;

typedef struct server_data_structure {
	int s_port;
} server_structure;

typedef struct ip_structure {
	unsigned char tag;
	union {
		client_structure *client_data;
		server_structure *server_data;
	} constant_union;
} ip_info;

typedef struct package_structure {
	u_int32_t dst_ip_addr;
	u_int8_t *payload;
} package_info;

#endif
