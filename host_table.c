#include "host_table.h"

extern redirect_table *table;

void add_host(u_int32_t src_ip, u_int32_t dst_ip, u_int32_t src_port, u_int32_t dst_port) {
	host_info *host;
	
	if (table == NULL || table->hosts == NULL) {
		table = malloc(sizeof(redirect_table));
		table->hosts = malloc(sizeof(host_info));
		table->hosts_count = 0;
		host = table->hosts;
	} else {
		table->hosts = realloc(table->hosts, sizeof(host_info)*(table->hosts_count+1));
		host = table->hosts + table->hosts_count;
	}

	host->src_ip = src_ip;
	host->dst_ip = dst_ip;
	host->src_port = src_port;
	host->dst_port = dst_port;
	
	
	table->hosts_count++;
	
}

host_info* search_by_src_ip(u_int32_t ip) {
	int index = 0;
	host_info *host;

	for (host = table->hosts; host < table->hosts+table->hosts_count; host++) {
		if (host->src_ip == ip) {
			return host;
		}
		index++;
	}
	return NULL;
}

