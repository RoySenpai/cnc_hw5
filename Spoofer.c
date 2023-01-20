/*
 *  Communication and Computing Course Assigment 5 Task B:
 *  Spoofer Application for ICMP, TCP and UDP packets
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

#define INVALID_SOCKET -1
#define PACKET_LEN 536
#define MTU 1500


/* IP Header settings */

/* IP version */
#define P_IP_VERSION	4

/* IP header length in words */
#define P_IP_HL			5

/* IP Time-To-Live (Short) */
#define P_IP_TTL		42

/* Source IP Address */
#define P_IP_SRC		"8.8.8.8"

/* Destenation IP Address */
#define P_IP_DST		"10.0.2.15"


#define P_ICMP_TYPE 	ICMP_ECHO
#define P_ICMP_CODE		0
#define P_ICMP_ECHO_ID	1332
#define P_ICMP_ECHO_SEQ	420
#define P_ICMP_MSG		"This is a spoofed ICMP message."

#define P_UDP_SPORT		32132
#define P_UDP_DPORT		12345
#define P_UDP_MSG		"This is a spoofed UDP message."

#define P_TCP_SPORT		32132
#define P_TCP_DPORT		12345
#define P_TCP_SEQ		432525
#define P_TCP_ACKSEQ	8676752
#define P_TCP_HL		5
#define P_TCP_FLGS		(TH_PUSH | TH_ACK)
#define P_TCP_WIN		1024
#define P_TCP_URP		0
#define P_TCP_MSG		"This is a spoofed TCP message."

unsigned short calculate_tcp_checksum(struct ip *iph);
unsigned short in_cksum(unsigned short *buf, int length);
unsigned short csum(unsigned short *ptr,int nbytes);
void send_raw_ip_packet(struct ip *iph);
void spoofICMP(struct ip *iph);
void spoofTCP(struct ip *iph);
void spoofUDP(struct ip *iph);

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

int main(int argc, char** args) {
	struct ip iph;

  	printf("\n    Spoofer Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
		 "This program comes with ABSOLUTELY NO WARRANTY.\n"
		 "This is free software, and you are welcome to redistribute it\n"
		 "under certain conditions; see `LICENSE' for details.\n\n");

	if (argc != 2)
    {
        fprintf(stderr, "[ERROR] Usage: ./Spoofer <icmp or udp or tcp>\n");
        exit(1);
    }

	else
	{
		memset(&iph, 0, sizeof(struct ip));

		iph.ip_v = P_IP_VERSION;
		iph.ip_hl = P_IP_HL;
		iph.ip_ttl = P_IP_TTL;
		iph.ip_src.s_addr = inet_addr(P_IP_SRC);
		iph.ip_dst.s_addr = inet_addr(P_IP_DST);

		if (!strcmp(args[1], "tcp"))
		{
			iph.ip_p = IPPROTO_TCP;
			printf("[INFO] Spoofing TCP packets...\n\n");

			while (1)
			{
				spoofTCP(&iph);
				sleep(1);
			}
		}

		else if (!strcmp(args[1], "udp"))
		{
			iph.ip_p = IPPROTO_UDP;

			printf("[INFO] Spoofing UDP packets...\n\n");

			while (1)
			{
				spoofUDP(&iph);
				sleep(1);
			}
		}

		else if (!strcmp(args[1], "icmp"))
		{
			iph.ip_p = IPPROTO_ICMP;

			printf("[INFO] Spoofing ICMP packets...\n\n");

			while (1)
			{
				spoofICMP(&iph);
				sleep(1);
			}	
		}

		else
		{
			fprintf(stderr, "[ERROR] Unknown protocol.\n");
			exit(1);
		}
	}

	return 0;
}

void spoofICMP(struct ip *iph) {
	struct icmphdr *icmp = NULL;

	char *msg = P_ICMP_MSG;
	char buffer[MTU] = { 0 };

	int msglen = (strlen(msg) + 1);

	static int seq_num = P_ICMP_ECHO_SEQ;
	static int counter = 1;

	memcpy(buffer, iph, iph->ip_hl*4);
	memcpy((buffer + (iph->ip_hl*4) + sizeof(struct icmphdr)), msg, msglen);

	iph = (struct ip *)buffer;
	icmp = (struct icmphdr *)(buffer + (iph->ip_hl*4));
	iph->ip_len = htons((iph->ip_hl*4) + sizeof(struct icmphdr) + msglen);

	icmp->type = P_ICMP_TYPE;
	icmp->code = P_ICMP_CODE;
	icmp->un.echo.id = P_ICMP_ECHO_ID;
	icmp->un.echo.sequence = seq_num++;
	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + msglen);

	printf("[INFO] Spoofing ICMP packet %d:\n"
		   "\t[IPv%hhu] SRC={%s}; DST={%s}; HL={%hhu bytes}; TTL={%hhu}\n"
		   "\t[ICMP] TYPE={%s}; CODE={%hhu}; ID={%hu}; SEQ={%hu}; CHECKSUM={0x%04X}; MSG={%s}\n",
		   counter,
		   P_IP_VERSION,
		   P_IP_SRC,
		   P_IP_DST,
		   P_IP_HL * 4,
		   P_IP_TTL,
		   (P_ICMP_TYPE == ICMP_ECHO ? "ICMP ECHO":"ICMP ECHO REPLAY"),
		   P_ICMP_CODE,
		   P_ICMP_ECHO_ID,
		   icmp->un.echo.sequence,
		   icmp->checksum,
		   P_ICMP_MSG);

	send_raw_ip_packet(iph);

	printf("[INFO] Packet %d sent (%hu bytes).\n\n", counter++, ntohs(iph->ip_len));
}

void spoofUDP(struct ip *iph){
	struct udphdr* udph = NULL;
	struct pseudo_header psh;

	char *msg = P_ICMP_MSG, *pseudogram;
	char buffer[MTU] = { 0 };

	int msglen = (strlen(msg) + 1), psize;

	static int counter = 1;

	memcpy(buffer, iph, iph->ip_hl*4);
	memcpy((buffer + (iph->ip_hl*4) + sizeof(struct udphdr)), msg, msglen);

	iph = (struct ip *)buffer;
	udph = (struct udphdr*)(buffer + (iph->ip_hl*4));

    iph->ip_len = htons((iph->ip_hl*4) + sizeof(struct udphdr) + msglen);

    udph->uh_sport = htons(P_UDP_SPORT);
   	udph->uh_dport = htons(P_UDP_DPORT);
    udph->uh_ulen = htons(sizeof(struct udphdr) + msglen);
    udph->uh_sum = 0;

	psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(msg);
    pseudogram = malloc(psize);

	if (pseudogram == NULL)
	{
		perror("malloc");
		exit(errno);
	}

    memcpy(pseudogram, ((char*)&psh), sizeof(struct pseudo_header));
    memcpy((pseudogram + sizeof(struct pseudo_header)), udph, (sizeof(struct udphdr) + strlen(msg)));

	udph->uh_sum = csum(((unsigned short*)pseudogram), psize);

	free(pseudogram);

	printf("[INFO] Spoofing UDP packet %d:\n"
		   "\t[IPv%hhu] SRC={%s}; DST={%s}; HL={%hhu bytes}; TTL={%hhu}\n"
		   "\t[UDP] SPORT={%hu}; DPORT={%hu}; CHECKSUM={0x%04X}; MSG={%s}\n",
		   counter,
		   P_IP_VERSION,
		   P_IP_SRC,
		   P_IP_DST,
		   (P_IP_HL * 4),
		   P_IP_TTL,
		   P_UDP_SPORT,
		   P_UDP_DPORT,
		   udph->uh_sum,
		   P_UDP_MSG
	);

	send_raw_ip_packet(iph);

	printf("[INFO] Packet %d sent (%hu bytes).\n\n", counter++, ntohs(iph->ip_len));
}

void spoofTCP(struct ip *iph) {
	struct tcphdr* tcph = NULL;

	char *msg = P_TCP_MSG;

	char buffer[MTU] = { 0 };

	int msglen = (strlen(msg) + 1);

	static int counter = 1, seq = P_TCP_SEQ, ack_seq = P_TCP_ACKSEQ;

	static const char* TCP_flags[6] = {
        "FIN",
        "SYN",
        "RST",
        "PUSH",
        "ACK",
        "URG"
    };

	memcpy(buffer, iph, iph->ip_hl*4);

	iph = (struct ip *)buffer;
	tcph = (struct tcphdr *)(buffer + (iph->ip_hl*4));

	if ((P_TCP_FLGS & TH_PUSH) == TH_PUSH)
		iph->ip_len = htons((iph->ip_hl*4) + (P_TCP_HL*4) + msglen);

	else
		iph->ip_len = htons((iph->ip_hl*4) + (P_TCP_HL*4));

	tcph->source = htons(P_TCP_SPORT);
	tcph->dest = htons(P_TCP_DPORT);
	tcph->seq = htonl(seq++);
	tcph->ack_seq = htonl(ack_seq++);
	tcph->doff = P_TCP_HL;
	tcph->th_flags = P_TCP_FLGS;
	tcph->th_win = htons(P_TCP_WIN);
	tcph->th_urp = htons(P_TCP_URP);
	tcph->th_sum = 0;
	tcph->th_sum = calculate_tcp_checksum(iph);

	if ((P_TCP_FLGS & TH_PUSH) == TH_PUSH)
		memcpy((buffer + (iph->ip_hl*4) + (P_TCP_HL*4)), msg, msglen);

	printf("[INFO] Spoofing TCP packet %d:\n"
		   "\t[IPv%hhu] SRC={%s}; DST={%s}; HL={%hhu bytes}; TTL={%hhu}\n"
		   "\t[TCP] SPORT={%hu}; DPORT={%hu}; SEQ={%u}; ACK_SEQ={%u}; HL={%hu}; FLAGS={",
		   counter,
		   P_IP_VERSION,
		   P_IP_SRC,
		   P_IP_DST,
		   (P_IP_HL * 4),
		   P_IP_TTL,
		   P_TCP_SPORT,
		   P_TCP_DPORT,
		   seq,
		   ack_seq,
		   (P_TCP_HL*4)
	);


	for (int i = 0; i < 6; ++i)
    {
        if (tcph->th_flags & (1 << i))
            printf(" %s", TCP_flags[i]);
    }

	printf(" }; CHECKSUM={0x%04X}; WIN={%hu bytes}; URP={%hu}", tcph->th_sum, P_TCP_WIN, P_TCP_URP);

	if ((P_TCP_FLGS & TH_PUSH) == TH_PUSH)
		printf("; MSG={%s}\n", P_TCP_MSG);
	
	else
		printf("\n");

	send_raw_ip_packet(iph);

	printf("[INFO] Packet %d sent (%hu bytes).\n\n", counter++, ntohs(iph->ip_len));
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

   return ((unsigned short) in_cksum(((unsigned short *)&p_tcp), (tcp_len + 12)));
}
