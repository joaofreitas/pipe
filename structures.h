#ifndef __STRUCTURES_H
#define __STRUCTURES_H
#define VERBOSE_MODE
#include <stdio.h>

typedef struct redirect_message_structure {
	char *dst_ip;
	u_int32_t dst_port;
} redirect_info;

typedef struct client_data_structure {
	u_int32_t s_port;
	u_int32_t d_port;
	char *ip_addr;
	redirect_info *redirect;
} client_structure;

typedef struct server_data_structure {
	u_int32_t s_port;
	redirect_info *redirect;
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
