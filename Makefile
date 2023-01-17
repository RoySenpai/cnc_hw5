CC = gcc
CFLAGS = -Wall -g

.PHONY: all clean

all: Sniffer Spoofer Gateway Snoofer

Sniffer: Sniffer.o
	$(CC) $(CFLAGS) $^ -lpcap -o $@

Spoofer: Spoofer.o
	$(CC) $(CFLAGS) $^ -o $@

Snoofer: Snoofer.o
	$(CC) $(CFLAGS) $^ -lpcap -o $@

Gateway: Gateway.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o Sniffer Spoofer Snoofer Gateway