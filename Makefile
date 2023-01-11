CC = gcc
CFLAGS = -Wall -g

.PHONY: all clean

all: Sniffer Spoofer Gateway

Sniffer: Sniffer.o
	$(CC) $(CFLAGS) $^ -lpcap -o $@

Spoofer: Spoofer.o
	$(CC) $(CFLAGS) $^ -o $@

Gateway: Gateway.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o Sniffer Spoofer Gateway