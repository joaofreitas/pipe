#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <unistd.h>
#include "sniffer.h"

int CLIENT = 0;
int SERVER = 1;

int main(int argc, char *argv[]) {
	ip_info *data;

	if (argc > 2) {
		data = malloc(sizeof(ip_info));

		if (strcmp(argv[1], "-S") == 0) {
			data->tag = SERVER;
			data->constant_union.server_data = malloc(sizeof(server_structure));
			data->constant_union.server_data->s_port = atoi(argv[2]);

			printf("Modo server. Porta %d.", data->constant_union.client_data->s_port);
			create_sniffer("wlan0", data);
		} else {
			data->tag = CLIENT;
			data->constant_union.client_data = malloc(sizeof(client_structure));
			data->constant_union.client_data->ip_addr = argv[1];
			data->constant_union.client_data->d_port = atoi(argv[2]);
			data->constant_union.client_data->s_port = 9000;		//Por enquanto, é a 9000

			printf("Iniciando modo cliente escutando porta %d (não foi passado -L) e enviando para %s:%d\n", 
					data->constant_union.server_data->s_port,
					data->constant_union.client_data->ip_addr,
					data->constant_union.client_data->d_port
					);
			create_sniffer("wlan0", data);
		}
	} else {
		printf("Exemplo de uso para server: ./pipe -S 1900\n");
		printf("Exemplo de uso para cliente: ./pipe 192.168.0.157 1234\n");
	}

	return 0;
}
