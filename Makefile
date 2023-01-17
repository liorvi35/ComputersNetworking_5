CC = gcc
FLAGS = -Wall -g
TARGETS = Sniffer Spoofer Sniff_and_spoof Gateway gatecheck

.PHONY: all clean

all: $(TARGETS)

b: Ping

Sniffer: Sniffer.o
	$(CC) $(FLAGS) -o Sniffer Sniffer.o -lpcap

Sniffer.o: Sniffer.c 
	$(CC) $(FLAGS) -c Sniffer.c

Spoofer: Spoofer.o
	$(CC) $(FLAGS) -o Spoofer Spoofer.o

Spoofer.o: Spoofer.c
	$(CC) $(FLAGS) -c Spoofer.c

Sniff_and_spoof: sniff_and_spoof.o
	$(CC) $(FLAGS) -o Sniff_and_spoof sniff_and_spoof.o -lpcap

sniff_and_spoof.o: sniff_and_spoof.c
	$(CC) $(FLAGS) -c sniff_and_spoof.c

Ping: ping.o
	$(CC) $(FLAGS) -o Ping ping.o 

ping.o: ping.c
	$(CC) $(FLAGS) -c ping.c

Gateway: gateway.o
	$(CC) $(FLAGS) -o Gateway gateway.o 

gateway.o: gateway.c
	$(CC) $(FLAGS) -c gateway.c

Gatecheck: gatecheck.o
	$(CC) $(FLAGS) -o Gatecheck gatecheck.o 

gatecheck.o: gatecheck.c
	$(CC) $(FLAGS) -c gatecheck.c
	

clean:
	rm -f *.o *.h.gch $(TARGETS) Ping gatecheck
