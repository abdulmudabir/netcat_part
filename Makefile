
# Makefile for netcat_part

cc=gcc

CFLAGS=-Wall -g

all: netcat

netcat: netcat.o client.o server.o
	$(CC) -lssl netcat.o client.o server.o -o netcat_part

netcat.o: netcat_part.c
	$(CC) $(CFLAGS) -c netcat_part.c -o netcat.o

client.o: client.c
	$(CC) $(CFLAGS) -c -lssl client.c -o client.o

server.o: server.c
	$(CC) $(CFLAGS) -c -lssl server.c -o server.o

clean:
	rm -f *.o *~ netcat_part

kleen:
	rm -f *.o *~ netcat_part results.txt tempFile.txt
