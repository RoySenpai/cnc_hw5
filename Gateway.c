/*
 *  Communication and Computing Course Assigment 5 Task B:
 *  Gateway Application for UDP packets
 *  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "net_head.h"

int main(int argc, char** args) {
    struct sockaddr_in server_recv, server_snd, client;

    char buf[1500];

    float rnd = 0.0;

    int socketfd_recv = INVALID_SOCKET, socketfd_snd = INVALID_SOCKET, bytes = 0;

    unsigned int clientlen = 0;

    printf("\n    Gateway Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
            "This program comes with ABSOLUTELY NO WARRANTY.\n"
            "This is free software, and you are welcome to redistribute it\n"
            "under certain conditions; see `LICENSE' for details.\n\n");

    if (argc != 2)
    {
        fprintf(stderr, "[ERROR] Usage: ./Gateway <ip address>\n");
        exit(1);
    }

    memset((char *) &server_recv, 0, sizeof(server_recv));
    memset((char *) &server_snd, 0, sizeof(server_snd));

    server_recv.sin_family = AF_INET;
    server_recv.sin_addr.s_addr = htonl(INADDR_ANY);
    server_recv.sin_port = htons(LISTEN_PORT);

    server_snd.sin_family = AF_INET;
    server_snd.sin_port = htons(SEND_PORT);

    if (inet_pton(AF_INET, args[1], &server_snd.sin_addr) <= 0)
    {
        fprintf(stderr, "[ERROR] Invalid IP Address.\n");
        exit(errno);
    }

	if ((socketfd_recv = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		perror("[ERROR] socket");
		exit(errno);
	}

    if ((socketfd_snd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		perror("[ERROR] socket");
		exit(errno);
	}

	if (bind(socketfd_recv, (struct sockaddr *) &server_recv, sizeof(server_recv)) == INVALID_SOCKET)
    {
        perror("[ERROR] bind");
        exit(errno);
    }

    printf("[INFO] Listening on UDP port %d, sending to IP address %s and UDP port %d...\n", LISTEN_PORT, args[1], SEND_PORT);
    printf("----------------------------------------------------------\n");

    while (1)
    {
        bzero(buf, sizeof(buf));
        memset((char *) &client, 0, sizeof(client));
        bytes = recvfrom(socketfd_recv, buf, sizeof(buf), 0, (struct sockaddr *) &client, &clientlen);

        printf("[INFO] Received %d bytes from client %s:%d.\n", bytes, inet_ntoa(client.sin_addr), LISTEN_PORT);
        
        rnd = ((float)random())/((float)RAND_MAX);

        if (rnd > 0.5)
        {
            if ((bytes = sendto(socketfd_snd, buf, bytes, 0, (struct sockaddr *)&server_snd, sizeof(struct sockaddr))) == INVALID_SOCKET)
            {
                perror("[ERROR] sendto");
                exit(errno);
            }

            printf("[INFO] Sent %d bytes to %s:%d.\n", bytes, args[1], SEND_PORT);
        }

        else
            printf("[INFO] Packet dropped.\n");
    }

    close(socketfd_snd);
    close(socketfd_recv);

    return 0;
}