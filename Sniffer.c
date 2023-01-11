#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>

typedef struct calculatorPacket {
    unsigned int unixtime;
    unsigned short length;
    unsigned short reserved:3,
    c_flag:1,
    s_flag:1,
    t_flag:1,
    status:10;
    unsigned short cache;
    unsigned short padding;
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
    struct ethhdr* ethheader = (struct ethhdr*)packet;
    
    if (ntohs(ethheader->h_proto) == ETH_P_IP)
    {
        struct ip* iph = (struct ip*)(packet + sizeof(struct ethhdr));

        if (iph->ip_p == IPPROTO_TCP)
        {
            struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ethhdr) + iph->ip_hl*4);

            if ((tcph->th_flags & TH_PUSH) != TH_PUSH)
                return;
                
            pcpack packdata = (struct calculatorPacket*)(packet + sizeof(struct ethhdr) + iph->ip_hl*4 + sizeof(struct tcphdr));

            printf("source_ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %d, total_length: %d, cache_flag: %d, steps_flag: %d, type_flag: %d, status_code: %d, cache_control: %d\n",
             inet_ntoa(iph->ip_src), 
             inet_ntoa(iph->ip_dst),
             tcph->th_sport,
             tcph->th_dport,
             packdata->unixtime,
             packdata->length,
             packdata->c_flag,
             packdata->s_flag,
             packdata->t_flag,
             packdata->status,
             packdata->cache
            );
        }
    }
}