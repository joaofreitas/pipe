NAME = pipe

CC = gcc

all : send_packet.o sniffer.o
	$(CC) -o $(NAME) main.c send_packet.o sniffer.o -g -Wall -lnet -lpcap
	make clean

send_packet.o:
	$(CC) -c send_packet.c

sniffer.o:
	$(CC) -c sniffer.c

clean :
	rm -rf *.o
	rm -rf *.gch
	rm -rf *~
