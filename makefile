NAME = pipe

CC = gcc

all : host_table.o send_packet.o sniffer.o
	$(CC) -o $(NAME) main.c send_packet.o sniffer.o -g -Wall -lnet -lpcap
	make clean

host_table.o:
	$(CC) -c host_table.c

send_packet.o:
	$(CC) -c send_packet.c

sniffer.o:
	$(CC) -c sniffer.c

clean :
	rm -rf *.o
	rm -rf *.gch
	rm -rf *~
