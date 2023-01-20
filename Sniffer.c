/*
 *  Communication and Computing Course Assigment 5 Task A:
 *  Sniffer Application for TCP connections of Calculator APP
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
#include <net/ethernet.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "net_head.h"

int main(int argc, char** args) {
    struct bpf_program filter;

    pcap_t *handle;

    char dev[MAX_DEV_NAME], error_buffer[PCAP_ERRBUF_SIZE], filter_exp[] = "tcp";

    bpf_u_int32 subnet_mask, ip;

    printf("\n    Sniffer Application;  Copyright (C) 2023  Roy Simanovich and Yuval Yurzdichinsky\n"
            "This program comes with ABSOLUTELY NO WARRANTY.\n"
            "This is free software, and you are welcome to redistribute it\n"
            "under certain conditions; see `LICENSE' for details.\n\n");

    if (argc == 1)
    {
        printf("[INFO] Using default network interface device.\n");
        strcpy(dev,"enp0s3");
    }

    else if (argc == 2)
        strcpy(dev,args[1]);

    else
    {
        fprintf(stderr, "[ERROR] Invalid arguments.\n");
        fprintf(stderr, "[ERROR] Usage: ./Sniffer <device name> or ./Sniffer\n");
        exit(1);
    }

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1)
    {
        fprintf(stderr, "[ERROR] Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);

    if (handle == NULL)
    {
        fprintf(stderr, "[ERROR] Could not open %s - %s\n", dev, error_buffer);
        exit(1);
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) 
    {
        fprintf(stderr, "[ERROR] Bad filter - %s\n", pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        fprintf(stderr, "[ERROR] Error setting filter - %s\n", pcap_geterr(handle));
        exit(1);
    }

    printf("[INFO] Listening to interface \"%s\" with filter \"%s\"...\n", dev, filter_exp);
    printf("----------------------------------------------------------\n");

    pcap_loop(handle, -1, packetSniffer, NULL);                

    pcap_close(handle);

    return 0;
}

void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {    
    static const char* TCP_flags[6] = {
        "FIN",
        "SYN",
        "RST",
        "PUSH",
        "ACK",
        "URG"
    };

    struct ethhdr* ethheader = (struct ethhdr*)packet;

    if (ntohs(ethheader->h_proto) != ETH_P_IP)
        return;

    struct iphdr* iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

    if (iph->protocol != IPPROTO_TCP)
        return;

    struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ethhdr) + iph->ihl*4);

    struct calculatorPacket* packdata = (struct calculatorPacket *)(packet + sizeof(struct ethhdr) + iph->ihl*4 + tcph->doff*4);

    struct tm ts;

    char sAddr[INET_ADDRSTRLEN] = { 0 }, dAddr[INET_ADDRSTRLEN] = { 0 }, buf[80] = { 0 };

    char* CalcData = NULL;

    static uint64_t frame = 0;

    time_t tt;

    uint32_t utime;

    uint16_t srcport, dstport, dlength, c_flag, s_flag, t_flag, scode, cachecontrol;

    FILE *fp = NULL;

    fp = fopen("log.txt", "a");

    if (fp == NULL)
    {
        perror("fopen");
        exit(errno);
    }

    inet_ntop(AF_INET, &(iph->saddr), sAddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dAddr, INET_ADDRSTRLEN);

    srcport = ntohs(tcph->source);
    dstport = ntohs(tcph->dest);

    printf("------------------\tFRAME %ld \t------------------\n", (++frame));
    printf("(*) Total Frame Size: %lu bytes\n", (sizeof(struct ethhdr) + ntohs(iph->tot_len)));
    printf("------------------\tETH HEADER\t------------------\n");
    printf("(*) Source MAC Address: ");

    for (int i = 0; i < ETH_ALEN; ++i)
        printf("%02x%c", ethheader->h_source[i], (i == (ETH_ALEN - 1) ? '\n':':'));

    printf("(*) Destenation MAC Address: ");

    for (int i = 0; i < ETH_ALEN; ++i)
        printf("%02x%c", ethheader->h_dest[i], (i == (ETH_ALEN - 1) ? '\n':':'));

    printf("(*) Protocol: Internet Protocol\n");

    printf("------------------\tIP HEADER \t------------------\n");
    printf("(*) Version: %hu\n"
            "(*) Header Length: %hu bytes\n"
            "(*) Type-Of-Service (TOS): %hu\n"
            "(*) Total Length: %hu bytes\n"
            "(*) Identification : %hu\n"
            "(*) Fragment Offset: %hu\n"
            "(*) Time-To-Live (TTL): %hu\n"
            "(*) Protocol: %hu (Transmission Control Protocol)\n"
            "(*) Header checksum: %hu\n"
            "(*) Source IP Address: %s\n"
            "(*) Destenation IP Address: %s\n",
            iph->version,
            iph->ihl*4,
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

    printf("------------------\tTCP HEADER\t------------------\n");
    printf("(*) Source Port: %hu\n"
           "(*) Destenation Port: %hu\n"
           "(*) Sequence Number: %u\n"
           "(*) Acknowledgment Number: %u\n"
           "(*) Header Length: %hu bytes\n"
           "(*) TCP Flags:",
           srcport,
           dstport,
           ntohl(tcph->th_seq),
           ntohl(tcph->th_ack),
           tcph->doff*4
    );

    for (int i = 0; i < 6; ++i)
    {
        if (tcph->th_flags & (1 << i))
            printf(" %s", TCP_flags[i]);
    }

    printf("\n");
    
    printf("(*) Window Size: %hu bytes\n"
           "(*) Checksum: %hu\n"
           "(*) Urgent pointer: %hu\n",
           ntohs(tcph->th_win),
           ntohs(tcph->th_sum),
           ntohs(tcph->th_urp)
    );

    if ((tcph->th_flags & TH_PUSH) != TH_PUSH)
    {
        printf("---------------s-------------------------------------------\n");
        return;
    }

    utime = ntohl(packdata->unixtime);
    dlength = ntohs(packdata->length);
    packdata->un.flags = ntohs(packdata->un.flags);
    c_flag = (((packdata->un.flags) >> 12) & 1);
    s_flag = (((packdata->un.flags) >> 11) & 1);
    t_flag = (((packdata->un.flags) >> 10) & 1);
    scode = packdata->un.status;
    cachecontrol = ntohs(packdata->cache);

    CalcData = malloc(dlength * sizeof(uint8_t));

    if (CalcData == NULL)
    {
        perror("malloc");
        exit(errno);
    }
    
    memcpy(CalcData, (packet + sizeof(struct ethhdr) + iph->ihl*4 + tcph->doff*4 + sizeof(struct calculatorPacket)), dlength);

    tt = utime;
    ts = *localtime(&tt);
    strftime(buf, sizeof(buf), "%a %d-%m-%Y %H:%M:%S", &ts);

    printf("------------------\tAPP HEADER\t------------------\n");
    printf("(*) Timestamp: %u (%s)\n"
           "(*) Total Length: %hu bytes\n"
           "(*) Cache Flag: %hu\n"
           "(*) Steps Flag: %hu\n"
           "(*) Type Flag: %hu\n"
           "(*) Status Code: %hu\n"
           "(*) Cache Control: %hu\n",
           utime,
           buf,
           dlength,
           c_flag,
           s_flag,
           t_flag,
           scode,
           cachecontrol);

    printf("------------------\tPAYLOAD\t\t------------------\n");
    for (int i = 0; i < dlength; ++i)
    {
        if (!(i & 15))
            printf("\n%04X: ", i);

        printf("%02X ", ((unsigned char *)CalcData)[i]);
    }

    printf("\n----------------------------------------------------------\n");

    fprintf(fp, "source_ip: %s, dest_ip: %s, source_port: %hu, "
                "dest_port: %hu, timestamp: %u, total_length: %hu cache_flag: %hu, "
                "steps_flag: %hu, type_flag: %hu, status_code: %u, cache_control: %hu, "
                "data:",
                sAddr,
                dAddr,
                srcport,
                dstport,
                utime,
                dlength,
                c_flag,
                s_flag,
                t_flag,
                scode,
                cachecontrol
    );

    for (int i = 0; i < dlength; ++i)
    {
        if (!(i & 15))
            fprintf(fp, "\n%04X: ", i);

        fprintf(fp, "%02X ", ((unsigned char *)CalcData)[i]);
    }

    fprintf(fp, "\n\n");

    free(CalcData);
    fclose(fp);
}
