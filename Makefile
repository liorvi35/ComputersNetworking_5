CC = gcc
FLAGS = -Wall -g
TARGETS = Sniffer Spoofer 

.PHONY: all clean

all: $(TARGETS)

Sniffer: Sniffer.o
	$(CC) $(FLAGS) -o Sniffer Sniffer.o -lpcap

Sniffer.o: Sniffer.c 
	$(CC) $(FLAGS) -c Sniffer.c

Spoofer: Spoofer.o
	$(CC) $(FLAGS) -o Spoofer Spoofer.o

Spoofer.o: Spoofer.c
	$(CC) $(FLAGS) -c Spoofer.c

clean:
	rm -f *.o *.h.gch $(TARGETS)
