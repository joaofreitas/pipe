#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <unistd.h>
#include "sniffer.h"

int main(int argc, char *argv[]) {
	int s_port;

	if (argc > 2) {
		if (strcmp(argv[1], "-s") == 0) {
			s_port = atoi(argv[2]);
			printf("Iniciando modo server na porta %d\n", s_port);
			create_sniffer("wlan0", s_port);
		} else {
			printf("nada iniciado.");
		}
	} else {
		printf("Não é o funcionamento correto desse programa...\n");
	}

	return 0;
}
