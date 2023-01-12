/*
 *  Communication and Computing Course Assigment 5:
 *  Sniffer and Spoofer
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
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#define CAL_HDRLEN 12
#define CAL_MAXSIZE 8180

typedef struct calculatorPacket {
    uint32_t unixtime;
    uint16_t length;
    uint16_t reserved:3,c_flag:1,s_flag:1,t_flag:1,status:10;
    uint16_t cache;
    uint16_t padding;
} cpack, *pcpack;

void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main() {
    struct bpf_program filter;

    pcap_t *handle;

    char dev[] = "lo";
    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp";

    bpf_u_int32 subnet_mask, ip;

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

    pcap_loop(handle, -1, packetSniffer, NULL);                

    pcap_close(handle);

    return 0;
}

void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static struct ethhdr* ethheader = NULL;
    static struct iphdr* iph = NULL;
    static struct tcphdr* tcph = NULL;
    static struct calculatorPacket* packdata = NULL;

    static uint16_t iphdr_size = 0, tcphdrlen = 0, srcport = 0, dstport = 0, totalhdrsize = 0, dlength = 0, scode = 0;

    static char sAddr[INET_ADDRSTRLEN] = { 0 }, dAddr[INET_ADDRSTRLEN] = { 0 };

    static char* TCP_flags[6] = {
        "FIN",
        "SYN",
        "RST",
        "PUSH",
        "ACK",
        "URG"
    };

    ethheader = (struct ethhdr*)packet;
    
    if (ntohs(ethheader->h_proto) == ETH_P_IP)
    {
        iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

        if (iph->protocol == IPPROTO_TCP)
        {
            iphdr_size = iph->ihl*4;

            tcph = (struct tcphdr*)(packet + iphdr_size + sizeof(struct ethhdr));

            inet_ntop(AF_INET, &(iph->saddr), sAddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iph->daddr), dAddr, INET_ADDRSTRLEN);

            tcphdrlen = tcph->doff*4;
            srcport = ntohs(tcph->th_sport);
            dstport = ntohs(tcph->th_dport);

            printf("----------------------------------\n");
            printf("Sniffed TCP packet:\n\n");
            printf("(*) Source IP Address: %s\n"
            "(*) Destenation IP Address: %s\n"
            "(*) Source Port: %hu\n"
            "(*) Destenation Port: %hu\n"
            "(*) TCP Flags:", 
             sAddr, 
             dAddr, 
             srcport, 
             dstport
            );

            for (int i = 0; i < 6; ++i)
            {
                if (tcph->th_flags & (1<<i))
                    printf(" %s", TCP_flags[i]);
            }
            
            printf("\n\n");

            if ((tcph->th_flags & TH_PUSH) != TH_PUSH)
                return;

            totalhdrsize = sizeof(struct ethhdr) + iphdr_size + tcphdrlen;
                
            packdata = (struct calculatorPacket*)(packet + totalhdrsize);
            dlength = ntohs(packdata->length);
            scode = (packdata->status)>>2;

            char CalcData[dlength];

            memcpy(CalcData, (packet + totalhdrsize + CAL_HDRLEN), dlength);

            printf("TCP Payload:\n");
            printf("(*) Timestamp: %u\n"
            "(*) Total length: %hu\n"
            "(*) Cache flag: %hu\n"
            "(*) Steps flag: %hu\n"
            "(*) Type flag: %hu\n"
            "(*) status code: %hu\n"
            "(*) Cache control: %hu\n",
             ntohl(packdata->unixtime),
             dlength,
             packdata->c_flag,
             packdata->s_flag,
             packdata->t_flag,
             scode,
             ntohs(packdata->cache)
            );

            printf("(*) Data:");
            for (int i = 0; i < dlength; ++i)
            {
                if (!(i&15)) 
                    printf("\n%04X:  ", i);

                printf("%02X ",((unsigned char*)CalcData)[i]);
            }

            printf("\n");
        }
    }
}