#include <stdlib.h>
#include <libnet.h>
#include <sys/types.h>
#include "structures.h"

int
init_context_libnet();

u_int32_t
convert_address(char *ip_addr_str);

int
send_data(u_int16_t sp, u_int16_t dp, u_int8_t *payload, u_int32_t payload_s, u_int32_t ip_addr);
