#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define INVALID_SOCKET -1
#define LISTEN_PORT 9998
#define SEND_PORT 9999

int main() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    unsigned int clientlen = 0;
    char buf[1500];
    int socketfd = INVALID_SOCKET, enable = 1, bytes = 0;

	if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == INVALID_SOCKET)
	{
		perror("socket");
		exit(errno);
	}

    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(LISTEN_PORT);

	if (bind(socketfd, (struct sockaddr *) &server, sizeof(server)) == INVALID_SOCKET)
    {
        perror("bind");
        exit(errno);
    }

    while (1)
    {
        bzero(buf, sizeof(buf));
        bytes = recvfrom(socketfd, buf, sizeof(buf)-1, 0, (struct sockaddr *) &client, &clientlen);
        printf("%s\n", buf);
    }

    close(socketfd);

    return 0;
}