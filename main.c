#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <unistd.h>
#include "sniffer.h"

int CLIENT = 0;
int SERVER = 1;

char *DEVICE="wlan0";

int main(int argc, char *argv[]) {
	ip_info *data;
	redirect_info *redirect_data;
	char delimitador[] = ":", *l_port, *r_host, *r_port;

	if (argc > 2) {
		data = malloc(sizeof(ip_info));

		if (strcmp(argv[1], "-S") == 0) {
			data->tag = SERVER;
			data->constant_union.server_data = malloc(sizeof(server_structure));
			data->constant_union.server_data->s_port = atoi(argv[2]);

			#ifdef VERBOSE_MODE
			printf("Modo server. Porta %d.", data->constant_union.client_data->s_port);
			#endif
			create_sniffer(DEVICE, data);
		} else if (strcmp(argv[1], "-L") == 0) {
			l_port = strtok(argv[2], delimitador);
			r_host = strtok(NULL, delimitador);
			r_port = strtok(NULL, delimitador);
			
			redirect_data = malloc(sizeof(redirect_info));
			redirect_data->dst_ip = r_host;
			redirect_data->dst_port = atoi(r_port);

			data->tag = CLIENT;
			data->constant_union.client_data = malloc(sizeof(client_structure));
			data->constant_union.client_data->ip_addr = argv[3];
			data->constant_union.client_data->d_port = atoi(argv[4]);
			data->constant_union.client_data->s_port = atoi(l_port);
			data->constant_union.client_data->redirect = redirect_data;

			#ifdef VERBOSE_MODE
			printf("Iniciando modo cliente escutando porta %s, enviar para %s:%d e o server reencaminha para %s:%d\n", 
					l_port,
					data->constant_union.client_data->ip_addr,
					data->constant_union.client_data->d_port,
					redirect_data->dst_ip,
					redirect_data->dst_port);
			#endif

			create_sniffer(DEVICE, data);

			return 0;
		} else {
			data->tag = CLIENT;
			data->constant_union.client_data = malloc(sizeof(client_structure));
			data->constant_union.client_data->ip_addr = argv[1];
			data->constant_union.client_data->d_port = atoi(argv[2]);
			data->constant_union.client_data->s_port = 9000;		//Por enquanto, é a 9000
			
			data->constant_union.client_data->redirect = NULL;

			printf("Iniciando modo cliente escutando porta padrão %d (não foi passado -L) e enviando para %s:%d\n", 
					data->constant_union.server_data->s_port,
					data->constant_union.client_data->ip_addr,
					data->constant_union.client_data->d_port
					);
			create_sniffer(DEVICE, data);
		}
	} else {
		printf("Exemplo de uso para server: ./pipe -S 1900\n");
		printf("Exemplos de uso para cliente:\n\t./pipe 192.168.0.157 1234\n");
		printf("\tsudo ./pipe -L 23000:127.0.0.1:15000 127.0.0.1 28000\n");
		
	}

	return 0;
}
