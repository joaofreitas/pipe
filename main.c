#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <unistd.h>
#include "sniffer.h"

int main(int argc, char *argv[]) {
	ip_info *data;
	unsigned char payload[] = "libnet :D";

/*
	if (argc > 2) {
		data = malloc(sizeof(ip_info));

		if (strcmp(argv[1], "-S") == 0) {
			data->tag = 0;
			data->constant_union.client_data = malloc(sizeof(client_structure));
			data->constant_union.client_data->s_port = atoi(argv[2]);

			printf("Iniciando modo server na porta %d\n", data->constant_union.client_data->s_port);
			create_sniffer("wlan0", data);
		} else {
			data->tag = 1;
			data->constant_union.server_data = malloc(sizeof(server_structure));
			data->constant_union.server_data->ip_addr = argv[2];
			data->constant_union.server_data->s_port = atoi(argv[3]);

			printf("Iniciando modo cliente enviando na porta %d\n", data->constant_union.server_data->s_port);
			create_sniffer("wlan0", data);
		}
	} else {
		printf("Não é o funcionamento correto desse programa...\n");
	}
*/

	if (send_data(22345, 22345, LIBNET_UDP_H, payload, sizeof(payload), "192.168.0.157") == -1) {
		printf("Deu pau\n");
	}

	return 0;
}
