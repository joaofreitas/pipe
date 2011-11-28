#include <stdlib.h>
#include <libnet.h>
#include <sys/types.h>
#include "structures.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int
init_context_libnet();

u_int32_t
convert_address(char *ip_addr_str);

int
send_data(u_int16_t dp, package_info *package, u_int32_t payload_s, u_int32_t ip_addr);
