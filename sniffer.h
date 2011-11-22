#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "structures.h"
#include "send_packet.h"

void
create_sniffer(const char *dev, const ip_info *data);
