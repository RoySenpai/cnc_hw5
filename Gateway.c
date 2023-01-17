#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define INVALID_SOCKET -1
#define LISTEN_PORT 15000
#define SEND_PORT 15001

#define IP_TO_ROOT  "8.8.8.8"

int main() {
    struct sockaddr_in server_recv, server_snd;
    struct sockaddr_in client;

    unsigned int clientlen = 0;

    char buf[1500];
    int socketfd_recv = INVALID_SOCKET, socketfd_snd = INVALID_SOCKET, bytes = 0, rnd = 0;

    printf("    Gateway Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
            "This program comes with ABSOLUTELY NO WARRANTY.\n"
            "This is free software, and you are welcome to redistribute it\n"
            "under certain conditions; see `LICENSE' for details.\n");

	if ((socketfd_recv = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		perror("socket");
		exit(errno);
	}

    if ((socketfd_snd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		perror("socket");
		exit(errno);
	}

    memset((char *) &server_recv, 0, sizeof(server_recv));
    memset((char *) &server_snd, 0, sizeof(server_snd));

    server_recv.sin_family = AF_INET;
    server_recv.sin_addr.s_addr = htonl(INADDR_ANY);
    server_recv.sin_port = htons(LISTEN_PORT);

    server_snd.sin_family = AF_INET;
    server_snd.sin_port = htons(SEND_PORT);
    server_snd.sin_addr.s_addr = inet_addr(IP_TO_ROOT);

	if (bind(socketfd_recv, (struct sockaddr *) &server_recv, sizeof(server_recv)) == INVALID_SOCKET)
    {
        perror("bind");
        exit(errno);
    }

    printf("Listening on UDP port %d, sending to UDP port %d...\n", LISTEN_PORT, SEND_PORT);

    while (1)
    {
        bzero(buf, sizeof(buf));
        bytes = recvfrom(socketfd_recv, buf, sizeof(buf), 0, (struct sockaddr *) &client, &clientlen);

        printf("Received %d bytes from client.\n", bytes);
        
        rnd = (rand() % 100);

        switch(rnd)
        {
            case 0 ... 49:
            {
                printf("Packet dropped.\n");
                break;
            }

            case 50 ... 99:
            {
                printf("Sending packet outside...\n");

                if ((bytes = sendto(socketfd_snd, buf, bytes, 0, (struct sockaddr *)&server_snd, sizeof(struct sockaddr))) == INVALID_SOCKET)
                {
                    perror("sendto");
                    exit(errno);
                }

                printf("Sent %d bytes to %s.\n", bytes, inet_ntoa(server_snd.sin_addr));
                break;
            }

            default:
                break;
        }

    }

    close(socketfd_recv);
    close(socketfd_snd);

    return 0;
}