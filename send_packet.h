#include <stdlib.h>
#include <libnet.h>
#include <sys/types.h>
#include "structures.h"

int
send_data(u_int16_t sp, u_int16_t dp, u_int16_t len, u_int8_t *payload, u_int32_t payload_s, char *ip_addr_str);
