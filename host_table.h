#include<stdio.h>
#include<stdlib.h>
#include <sys/types.h>

typedef struct host_structure {
	u_int32_t src_ip;
	u_int32_t dst_ip;
	u_int32_t src_port;
	u_int32_t dst_port;
} host_info;

typedef struct redirect_table_structure {
	u_int32_t hosts_count;
	host_info *hosts;
} redirect_table;

void 
add_host(u_int32_t src_ip, u_int32_t dst_ip, u_int32_t src_port, u_int32_t dst_port);

host_info*
search_by_src_ip(u_int32_t ip);
