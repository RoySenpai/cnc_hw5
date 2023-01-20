CC = gcc
CFLAGS = -Wall -g

.PHONY: all clean

all: Sniffer Spoofer Gateway Snooper

Sniffer: Sniffer.o
	$(CC) $(CFLAGS) $^ -lpcap -o $@

Spoofer: Spoofer.o
	$(CC) $(CFLAGS) $^ -o $@

Snooper: Snooper.o
	$(CC) $(CFLAGS) $^ -lpcap -o $@

Gateway: Gateway.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c net_head.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o Sniffer Spoofer Snooper Gateway