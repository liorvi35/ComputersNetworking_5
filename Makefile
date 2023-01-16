CC = gcc
FLAGS = -Wall -g
TARGETS = Sniffer Spoofer Gateway Docker

.PHONY: all clean

all: Sniffer

Sniffer: Sniffer.o
	$(CC) $(FLAGS) -o Sniffer Sniffer.o -lpcap

Sniffer.o: Sniffer.c 
	$(CC) $(FLAGS) -c Sniffer.c

clean:
	rm -f *.o *.h.gch $(TARGETS)
