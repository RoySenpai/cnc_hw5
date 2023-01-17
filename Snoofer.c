/*
 *  Communication and Computing Course Assigment 5 Task B:
 *  Snoofer Application for ICMP packets
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

    // Defualt virtual box interface
    //char dev[] = "enp0s3";

    // Docker interface, change this to your docker local network.
    char dev[] = "br-3ec0d042eba1";

    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "icmp";

    bpf_u_int32 subnet_mask, ip;

    printf("    Snoofer Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
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
    struct iphdr* iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    struct icmphdr* icmph = (struct icmphdr*)(packet + sizeof(struct ethhdr) + iph->ihl*4);
    static char sAddr[INET_ADDRSTRLEN] = { 0 }, dAddr[INET_ADDRSTRLEN] = { 0 };

    static int frame = 0;

    // Filter non ping packets
    if (icmph->type != ICMP_ECHO)
        return;

    inet_ntop(AF_INET, &(iph->saddr), sAddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dAddr, INET_ADDRSTRLEN);

    printf("Cought ICMP Echo Request packet (seq = %d).\n",(++frame));
    printf("Source: {%s}; Destenation: {%s}\n", sAddr, dAddr);

    char buffer[1500] = { 0 };

    memcpy(buffer, (packet + sizeof(struct ethhdr)), (header->len - sizeof(struct ethhdr)));

    struct iphdr* iph_spoofed = (struct iphdr*)(buffer);
    struct icmphdr* icmph_spoofed = (struct icmphdr*)(buffer + iph->ihl*4);

    iph_spoofed->saddr = iph->daddr;
    iph_spoofed->daddr = iph->saddr;

    icmph_spoofed->type = ICMP_ECHOREPLY;
    icmph_spoofed->checksum = 0;
    icmph_spoofed->checksum = in_cksum((unsigned short *)icmph_spoofed, (header->len - sizeof(struct ethhdr) - iph->ihl*4));

    send_raw_ip_packet(iph_spoofed);
    printf("Spoofed ICMP Echo Replay sent.\n");
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