/*
 *  Communication and Computing Course Assigment 5 Task B:
 *  SPoofer Application for ICMP packets
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
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define INVALID_SOCKET -1
#define PACKET_LEN 536
#define MTU 1500

#define TYPE IPPROTO_TCP

unsigned short calculate_tcp_checksum(struct ip *iph);
unsigned short in_cksum(unsigned short *buf, int length);
unsigned short csum(unsigned short *ptr,int nbytes);
void send_raw_ip_packet(struct ip *iph);
void spoofICMP();
void spoofTCP();
void spoofUDP();

struct pseudo_tcp
{
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcphdr tcp;
    char payload[PACKET_LEN];
};

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

int main() {

  	printf("    Spoofer Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
		 "This program comes with ABSOLUTELY NO WARRANTY.\n"
		 "This is free software, and you are welcome to redistribute it\n"
		 "under certain conditions; see `LICENSE' for details.\n");
    printf("----------------------------------------------------------\n");

	switch (TYPE)
	{
		case IPPROTO_TCP:
		{
			printf("Spoofing TCP packet...\n");
			spoofTCP();
			break;
		}

		case IPPROTO_UDP:
		{
			printf("Spoofing UDP packet...\n");
			spoofUDP();
			break;
		}

		case IPPROTO_ICMP:
		{
			printf("Spoofing ICMP packet...\n");
			spoofICMP();
			break;
		}

		default:
		{
			printf("Unsupported protocol.\n");
			break;
		}
	}

	return 0;
}

void spoofICMP() {
	struct ip *iph = NULL;
	struct icmphdr *icmp = NULL;
	char buffer[MTU] = {0};
	char *msg = "SHUT UP";
	int msglen = (strlen(msg) + 1);

	memcpy(buffer + sizeof(struct ip) + sizeof(struct icmphdr), msg, msglen);

	icmp = (struct icmphdr *)(buffer + sizeof(struct ip));
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = 1332;
	icmp->un.echo.sequence = 420;
	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + msglen);

	iph = (struct ip *)buffer;
	iph->ip_v = 4;
	iph->ip_hl = 5;
	iph->ip_ttl = 69;
	iph->ip_src.s_addr = inet_addr("8.8.8.8");
	iph->ip_dst.s_addr = inet_addr("10.0.2.15");
	iph->ip_p = IPPROTO_ICMP;
	iph->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr) + msglen + 69);

	send_raw_ip_packet(iph);
}

void spoofUDP(){
    char buffer[MTU] = { 0 };
	struct ip* iph = (struct ip*)(buffer);
    struct udphdr* udph = (struct udphdr *) (buffer + sizeof(struct ip));
	char *msg = "Spoofed UDP message.";
	int msglen = (strlen(msg) + 1);

	iph->ip_v = 4;
	iph->ip_hl = 5;
	iph->ip_ttl = 64;
	iph->ip_src.s_addr = inet_addr("1.2.3.4");
	iph->ip_dst.s_addr = inet_addr("10.0.2.15");
    iph->ip_p = IPPROTO_UDP;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + msglen);

    udph->uh_sport = htons(54321);
   	udph->uh_dport = htons(12345);
    udph->uh_ulen = htons(sizeof(struct udphdr) + msglen);
    udph->uh_sum = 0;

	memcpy((buffer + sizeof(struct ip) + sizeof(struct udphdr)), msg, msglen);

	char *pseudogram;
	struct pseudo_header psh;

	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(msg);
    pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(msg));

	udph->uh_sum = csum( (unsigned short*) pseudogram , psize);

	free(pseudogram);

	send_raw_ip_packet(iph);
}

void spoofTCP() {
	char buffer[MTU] = { 0 };
	struct ip* iph = (struct ip*)(buffer);
    struct tcphdr* tcph = (struct tcphdr *) (buffer + sizeof(struct ip));
	char *msg = "Spoofed TCP message.";
	int msglen = (strlen(msg) + 1);

	iph->ip_v = 4;
	iph->ip_hl = 5;
	iph->ip_ttl = 64;
	iph->ip_src.s_addr = inet_addr("1.2.3.4");
	iph->ip_dst.s_addr = inet_addr("10.0.2.15");
    iph->ip_p = IPPROTO_TCP;
    iph->ip_len = htons(sizeof(struct ip) + tcph->doff*4 + msglen);

	tcph->source = htons(54321);
	tcph->dest = htons(12345);
	tcph->seq = htons(rand());
	tcph->ack_seq = htons(rand());
	tcph->doff = 5;
	tcph->th_flags = TH_ACK;
	tcph->th_urp = 0;
	tcph->th_sum = calculate_tcp_checksum(iph);

	memcpy((buffer + sizeof(struct ip) + tcph->doff*4 + msglen), msg, msglen);

	send_raw_ip_packet(iph);
}

unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
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

void send_raw_ip_packet(struct ip *iph) {
	struct sockaddr_in dest_info;
	int socketfd = INVALID_SOCKET, enable = 1;

	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = iph->ip_dst;

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

	if (sendto(socketfd, iph, ntohs(iph->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) == INVALID_SOCKET)
	{
		perror("sendto");
		exit(errno);
	}

	close(socketfd);
}

unsigned short calculate_tcp_checksum(struct ip *iph) {
   struct tcphdr *tcp = (struct tcphdr *)((u_char *)iph + sizeof(struct ip));

   int tcp_len = ntohs(iph->ip_len) - sizeof(struct ip);

   /* pseudo tcp header for the checksum computation */
   struct pseudo_tcp p_tcp;
   memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

   p_tcp.saddr = iph->ip_src.s_addr;
   p_tcp.daddr = iph->ip_dst.s_addr;
   p_tcp.mbz = 0;
   p_tcp.ptcl = IPPROTO_TCP;
   p_tcp.tcpl = htons(tcp_len);
   memcpy(&p_tcp.tcp, tcp, tcp_len);

   return  (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}
