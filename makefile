NAME = pipe

CC = gcc

all : sniffer.o
	$(CC) -o $(NAME) main.c sniffer.o -g -Wall -lnet -lpcap
	make clean

sniffer.o:
	$(CC) -c sniffer.c

clean :
	rm -rf *.o
	rm -rf *~
