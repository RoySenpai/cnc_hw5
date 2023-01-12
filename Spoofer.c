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
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

char* ICMP_TYPE_RESERVED = "RESERVED";

const char* ICMP_TYPES[256] = {
	"Echo Replay", 						/* 0 Echo reply (used to ping) */

	/* 1 and 2 Reserved */
	"", "",

	"Destination Unreachable",			/* 3 */
	"Source Quench", 					/* 4 Source quench (congestion control), deprecated */
	"Redirect Message",					/* 5 */
	"Alternate Host Address", 			/* 6 Deprecated */
	"",						  			/* 7 Reserved */
	"Echo Request",			  			/* 8 Echo request (used to ping) */
	"Router Advertisement",				/* 9 Router Advertisement  */
	"Router Solicitation",				/* 10 Router discovery/selection/solicitation */
	"Time Exceeded",					/* 11 */
	"Parameter Problem: Bad IP header", /* 12 */
	"Timestamp", 						/* 13 */				
	"Timestamp Reply",					/* 14 */
	"Information Request",				/* 15 Deprecated */
	"Information Reply",				/* 16 Deprecated */
	"Address Mask Request",				/* 17 Deprecated */
	"Address Mask Reply",				/* 18 Deprecated */
	"",									/* 19 Reserved for security */

	/* 20 through 29 Reserved for robustness experiment */
	"", "", "", "", "", "", "", "", "", "", 

	"Traceroute",						/* 30 Deprecated Information Request */
	"Datagram Conversion Error",		/* 31 Deprecated */
	"Mobile Host Redirect",				/* 32 Deprecated */
	"Where-Are-You",					/* 33 Deprecated originally meant for IPv6 */
	"Here-I-Am",						/* 34 Deprecated originally meant for IPv6 */
	"Mobile Registration Request",		/* 35 Deprecated */
	"Mobile Registration Reply",		/* 36 Deprecated */
	"Domain Name Request",				/* 37 Deprecated */
	"Domain Name Reply",				/* 38 Deprecated */
	"SKIP",								/* 39 SKIP Algorithm Discovery Protocol, Simple Key-Management for Internet Protocol */
	"Photuris",							/* 40 Photuris, Security failures */
	"Experimental",						/* 41 ICMP for experimental mobility protocols such as Seamoby [RFC4065] */
	"Extended Echo Request",			/* 42 Xping request */
	"Extended Echo Reply",				/* 43 Xping replay */

	/* 44 through 254 Reserved */
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",

	"Experimental",						/* 253 RFC3692-style Experiment 1 (RFC 4727) */
	"Experimental",						/* 254 RFC3692-style Experiment 2 (RFC 4727) */
	""									/* 255 Reserved */
};

const char* ICMP_DEST_UNREACH_CODES[16] = {
	"Destination network unreachable", "Destination host unreachable", "Destination protocol unreachable", "Destination port unreachable",
	"Fragmentation required, and DF flag se", "Source route failed", "Destination network unknown", "Destination host unknown",
	"Source host isolated", "Network administratively prohibited", "Host administratively prohibited", "Network unreachable for ToS",
	"Host unreachable for ToS", "Communication administratively prohibited", "Host Precedence Violation", "Precedence cutoff in effect"
};

const char* ICMP_REDIRECT_CODES[4] = {
	"Redirect Datagram for the Network",
	"Redirect Datagram for the Host",
	"Redirect Datagram for the ToS & network",
	"Redirect Datagram for the ToS & host"
};

const char* ICMP_PARAMETERPROB_CODES[3] = {
	"Pointer indicates the error",
	"Missing a required option",
	"Bad length"
};

const char* ICMP_EXT_ECHOREPLY_CODES[5] = {
	"No Error",
	"Malformed Query",
	"No Such Interface",
	"No Such Table Entry",
	"Multiple Interfaces Satisfy Query"
};


void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
unsigned short calculate_checksum(unsigned short *paddress, int len);

int main() {
	pcap_t *handle;

	char dev[] = "enp0s3";
	char error_buffer[PCAP_ERRBUF_SIZE];

	bpf_u_int32 subnet_mask, ip;

	printf("    Spoofer Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
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

	printf("Listening to interface \"%s\"...\n", dev);
	printf("----------------------------------------------------------\n");

	pcap_loop(handle, -1, packetSniffer, NULL);

	pcap_close(handle);

	return 0;
}

void send_raw_ip_packet(struct ip* ip);

void sendSpoofPacket(const u_char *packet, struct iphdr* ip, struct icmphdr *icmph);

void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct ethhdr *ethheader = (struct ethhdr *)packet;

	if (ntohs(ethheader->h_proto) != ETH_P_IP)
		return;

	struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));

	if (iph->protocol != IPPROTO_ICMP)
		return;

	struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethhdr) + (iph->ihl * 4));

	char sAddr[INET_ADDRSTRLEN] = {0}, dAddr[INET_ADDRSTRLEN] = {0};

	static uint64_t frame = 0;

	inet_ntop(AF_INET, &(iph->saddr), sAddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iph->daddr), dAddr, INET_ADDRSTRLEN);

	printf("------------------\tFRAME %ld \t------------------\n", (++frame));
	printf("(*) Total Frame Size: %lu bytes\n", (sizeof(struct ethhdr) + ntohs(iph->tot_len)));
	printf("------------------\tETH HEADER\t------------------\n");
	printf("(*) Source MAC Address: ");

	for (int i = 0; i < ETH_ALEN; ++i)
		printf("%02x%c", ethheader->h_source[i], (i == (ETH_ALEN - 1) ? '\n' : ':'));

	printf("(*) Destenation MAC Address: ");

	for (int i = 0; i < ETH_ALEN; ++i)
		printf("%02x%c", ethheader->h_dest[i], (i == (ETH_ALEN - 1) ? '\n' : ':'));

	printf("(*) Protocol: Internet Protocol\n");

	printf("------------------\tIP HEADER \t------------------\n");
	printf("(*) Version: %hu\n"
		   "(*) Header Length: %hu bytes\n"
		   "(*) Type-Of-Service (TOS): %hu\n"
		   "(*) Total Length: %hu bytes\n"
		   "(*) Identification : %hu\n"
		   "(*) Fragment Offset: %hu\n"
		   "(*) Time-To-Live (TTL): %hu\n"
		   "(*) Protocol: %hu\n"
		   "(*) Header Checksum: %hu\n"
		   "(*) Source IP Address: %s\n"
		   "(*) Destenation IP Address: %s\n",
		   iph->version,
		   iph->ihl * 4,
		   iph->tos,
		   ntohs(iph->tot_len),
		   iph->id,
		   iph->frag_off,
		   iph->ttl,
		   iph->protocol,
		   iph->check,
		   sAddr,
		   dAddr
	);

	printf("------------------\tICMP HEADER\t------------------\n");
	printf("(*) Type: %hhu (%s)\n"
		   "(*) Code: %hhu",
		   icmph->type,
		   ICMP_TYPES[icmph->type],
		   icmph->code
	);

	switch(icmph->type)
	{
		case ICMP_DEST_UNREACH:
		{
			printf(" (%s)\n", ICMP_DEST_UNREACH_CODES[icmph->code]);
			break;
		}

		case ICMP_PARAMETERPROB:
		{
			printf(" (%s)\n", ICMP_PARAMETERPROB_CODES[icmph->code]);
			break;
		}

		case ICMP_EXT_ECHOREPLY:
		{
			printf(" (%s)\n", ICMP_EXT_ECHOREPLY_CODES[icmph->code]);
			break;
		}

		default:
		{
			printf("\n");
			break;
		}
	}

	printf("(*) Checksum: %hu\n", ntohs(icmph->checksum));

	if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY)
	{
		printf("(*) Identifier: %hu\n"
			   "(*) Sequence Number: %hu\n",
			   ntohs(icmph->un.echo.id),
			   ntohs(icmph->un.echo.sequence)
		);


		//if (icmph->type == ICMP_ECHOREPLY)
		//{

			printf("------------------\tSPOOFING\t------------------\n");
			printf("Spoofing and sending...\n");
			sendSpoofPacket((packet + sizeof(struct ethhdr)), iph, icmph);
		//}
	}

}

void sendSpoofPacket(const u_char *packet, struct iphdr* ip, struct icmphdr *icmph) {
	struct ip *iptosend;
	struct icmphdr *icmptosend;
	struct in_addr saddr;
	struct in_addr daddr;
	unsigned short plen = ntohs(ip->tot_len) - ip->ihl*4 - sizeof(struct icmphdr);

	u_char bufferToSend[1500] = { 0 };

	iptosend = (struct ip*)bufferToSend;
	iptosend->ip_v = ip->version;
	iptosend->ip_hl = 5;
	iptosend->ip_ttl = 20;
	iptosend->ip_p = IPPROTO_ICMP; 
	iptosend->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr));

	icmptosend = (struct icmphdr*)(bufferToSend + sizeof(struct ip));
	
	icmptosend->type = icmph->type;
	icmptosend->code = icmph->code;
	icmptosend->un.echo.id = icmph->un.echo.id;
	icmptosend->un.echo.sequence = icmph->un.echo.sequence;

	if (icmph->type == ICMP_ECHO)
	{
		printf("Echo Request packet detected\n");		
		saddr.s_addr = inet_addr("255.0.255.1");
		daddr.s_addr = ip->saddr;

		icmptosend->type = ICMP_ECHOREPLY;
	}

	else if (icmph->type == ICMP_ECHOREPLY)
	{
		printf("Echo Replay packet detected\n");
		saddr.s_addr = inet_addr("255.0.255.1");
		daddr.s_addr = ip->daddr;
	}

	iptosend->ip_src = saddr;
	iptosend->ip_dst = daddr;

	icmptosend->checksum = 0;

	icmptosend->checksum = calculate_checksum((unsigned short *)(bufferToSend + (iptosend->ip_hl*4)), sizeof(struct icmphdr));
    memcpy((bufferToSend + (iptosend->ip_hl*4)), icmptosend, sizeof(struct icmphdr));

	send_raw_ip_packet(iptosend);

	printf("Spoofed packet sent.\n");
}

void send_raw_ip_packet(struct ip* ip) {
    struct sockaddr_in dest_info;

    int enable = 1, sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if (sock == -1)
	{
		perror("socket");
		exit(errno);
	}

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) == -1)
	{
		perror("setsockopt");
		exit(errno);
	}

    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->ip_dst;

    if (sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) == -1)
	{
		perror("sendto");
		exit(errno);
	}

    close(sock);
}

unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len, sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}