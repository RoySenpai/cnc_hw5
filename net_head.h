/*
 *  Communication and Computing Course Assigment 5
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

#ifndef _NET_HEAD_H
#define _NET_HEAD_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pcap.h>

/****************************************/
/*************** Constants **************/
/****************************************/

/* For PCAP library: Maximum length of the name of a 
    network interface card (NIC). */
#define MAX_DEV_NAME                128

/* Constant for invalid sockets. */
#define INVALID_SOCKET              -1

/* Gateway: Listening port for UDP data transfer. */
#define LISTEN_PORT                 15000

/* Gateway: Forwarding port for UDP data transfer. */
#define SEND_PORT                   15001

/* Default Maximum Transmission Unit (MTU) across WAN networks. */
#define MTU                         1500


/**********************************/
/******* IP Header settings *******/
/**********************************/

/* IP version */
#define P_IP_VERSION                4

/* IP header length in words */
#define P_IP_HL                     5

/* IP Time-To-Live (Short) */
#define P_IP_TTL                    42

/* Source IP Address */
#define P_IP_SRC                    "8.8.8.8"

/* Destenation IP Address */
#define P_IP_DST                    "10.0.2.15"


/************************************/
/******* ICMP Header settings *******/
/************************************/

/* ICMP packet type (ICMP_ECHO = 8; ICMP_ECHOREPLAY = 0). */
#define P_ICMP_TYPE                 ICMP_ECHO

/* ICMP packet code (for Echo's its always 0). */
#define P_ICMP_CODE                 0

/* ICMP Echo identification code. */
#define P_ICMP_ECHO_ID              1332

/* ICMP Echo starting sequance number. */
#define P_ICMP_ECHO_SEQ             420

/* ICMP packet payload: the message itself that's carried. */
#define P_ICMP_MSG                  "This is a spoofed ICMP message."


/***********************************/
/******* UDP Header settings *******/
/***********************************/

/* UDP packet source port. */
#define P_UDP_SPORT                 32132

/* UDP packet destenation port. */
#define P_UDP_DPORT                 12345

/* UDP packet payload: the message itself that's carried. */
#define P_UDP_MSG                   "This is a spoofed UDP message."


/***********************************/
/******* TCP Header settings *******/
/***********************************/

/* TCP packet source port. */
#define P_TCP_SPORT                 32132

/* TCP packet destenation port. */
#define P_TCP_DPORT                 12345

/* TCP packet starting sequance number. */
#define P_TCP_SEQ                   432525

/* TCP packet starting ACK sequance number. */
#define P_TCP_ACKSEQ                8676752

/* TCP header length in words. */
#define P_TCP_HL                    5

/*
 * TCP header flags
 * --------------------
 ** TH_URG – Data inside a segment with URG = 1 flag is forwarded to application layer immediately
 *              even if there are more data to be given to application layer. It is used to notify
 *              the receiver to process the urgent packets before processing all other packets.
 *              The receiver will be notified when all known urgent data has been received.
 *
 ** TH_ACK – It is used to acknowledge packets which are successful received by the host.
 *              The flag is set if the acknowledgement number field contains a valid acknowledgement number.
 *              In given below diagram, the receiver sends an ACK = 1 as well as SYN = 1 in the second
 *              step of connection establishment to tell sender that it received its initial packet.
 *
 ** TH_PUSH – Transport layer by default waits for some time for application layer to send enough
 *              data equal to maximum segment size so that the number of packets transmitted on network
 *              minimizes which is not desirable by some application like interactive applications(chatting).
 *              Similarly transport layer at receiver end buffers packets and transmit to application layer
 *              if it meets certain criteria.  This problem is solved by using PSH. Transport layer
 *              sets PSH = 1 and immediately sends the segment to network layer as soon as it receives signal
 *              from application layer. Receiver transport layer, on seeing PSH = 1 immediately forwards the
 *              data to application layer. In general, it tells the receiver to process these packets as
 *              they are received instead of buffering them.
 *
 ** TH_RST – It is used to terminate the connection if the RST sender feels something is wrong with the TCP
 *              connection or that the conversation should not exist. It can get send from receiver side when
 *              packet is send to particular host that was not expecting it.
 *
 ** TH_SYN – It is used in first step of connection establishment phase or 3-way handshake process between the
 *              two hosts. Only the first packet from sender as well as receiver should have this flag set.
 *              This is used for synchronizing sequence number i.e. to tell the other end which sequence
 *              number they should accept.
 *
 ** TH_FIN – It is used to request for connection termination i.e. when there is no more data from the sender,
 *              it requests for connection termination. This is the last packet sent by sender. It frees the
 *              reserved resources and gracefully terminate the connection.
 *
 */
#define P_TCP_FLGS                  (TH_PUSH | TH_ACK)

/* TCP packet window size. */
#define P_TCP_WIN                   1024

/* TCP packet urgent number.
    Valid only when URG flag is on. */
#define P_TCP_URP                   0

/* TCP packet payload: the message itself that's carried.
    Used only if the PUSH flag is on. */
#define P_TCP_MSG                   "This is a spoofed TCP message."


/****************************************/
/**************** Structs ***************/
/****************************************/

/*
 * Struct: Calculator Application Packet Header
 * Size: 12 bytes (3 words)
 * --------------------
 *  This struct represents the calculator application header from Ex2.
 * 
*/
struct calculatorPacket
{
    /*
     *
     * Field: Unix Time Stamp
     * Size: 4 bytes (32 bits)
     * --------------------
     *  The time that the packet was sent, in seconds since 1970-01-01 00:00:00 UTC.
     *
     */
    uint32_t unixtime;

    /*
     *
     * Field: Total Length
     * Size: 2 bytes (16 bits)
     * --------------------
     *  The total length of the packet, in bytes (including the header and the data).
     *  The minimum value is 12 bytes (header only) and the maximum value is 8180 bytes.
     *
     */
    uint16_t length;

    /*
     * Union struct to use the netowrk byte-order to host byte-order to all fields
     * at one time.
     */
    union
    {
        /*
          *
          * Field: Flags
          * Size: 2 bytes (16 bits)
          * --------------------
          *  Used to extract the flags using bitwise.
          *
         */
        uint16_t flags;

        /*
          *
          * Field: Reserved
          * Size: 3 bits
          * --------------------
          *  Reserved for future use (must be 0).
          *
         */
        uint16_t _ : 3,

        /*
         *
         * Field: Cache
         * Size: 1 bit
         * --------------------
         *  Whether to cache the packet or not
         *  (1 = cache/cached, 0 = don't cache/didn't cache).
         *
        */
        c_flag : 1,

        /*
         *
         * Field: Steps
         * Size: 1 bit
         * --------------------
         *  Whether to include the computation steps in the response
         *  (1 = include/included, 0 = don't include/didn't include).
         *
        */
        s_flag : 1,

        /*
         *
         * Field: Type
         * Size: 1 bit
         * --------------------
         *  Whether the packet is a request (1 = request, 0 = response).
         *
        */
        t_flag : 1,

        /*
         *
         * Field: Status Code
         * Size: 10 bits
         * --------------------
         *  The status code of the response (only valid if the packet is a response).
         *  2xx = success, 4xx = client error, 5xx = server error, 0 = not a response.
         *
        */
        status : 10;
    } un;

    /*
     *
     * Field: Cache Control (16 bits = 2 bytes)
     * Size: 2 bytes (16 bits)
     * --------------------
     *  'Max-Age' value for the cache. If the 'Cache' flag is not set, this value is
     *  ignored. If the value is the maximum value for a 16-bit unsigned integer (65535),
     *  the cache will never expire. For requests, this is the maximum age of the cached
     *  response that the client is willing to accept (in seconds). This means that the
     *  cache shouldn't return a cached response older then this value. If max-age is 0,
     *  the server must recompute the response regardless of whether it is cached or not.
     *  For responses, this is the maximum time that the response can be cached for
     *  (in seconds). If max-age is 0, the response must not be cached.
     *
     */
    uint16_t cache;

    /*
     *
     * Field: Padding
     * Size: 2 bytes (16 bits)
     * --------------------
     *  Padding for future use (must be 0).
     *
     */
    uint16_t __;
};


/*
 * Struct: TCP pseudo header
 * Size: 1500 bytes (375 words)
 * --------------------
 *  A pesudo header of TCP packet, used to calculate packet's checksum.
 * 
*/
struct pseudo_tcp
{
    /*
     *
     * Field: Source IPv4 address
     * Size: 4 bytes (32 bits)
     * --------------------
     *  The source IP address of the packet.
     *
    */
    u_int32_t saddr;

    /*
     *
     * Field: Source IPv4 address
     * Size: 4 bytes (32 bits)
     * --------------------
     *  The destenation IP address of the packet.
     *
    */
    u_int32_t daddr;

    /*
     *
     * Field: Padding
     * Size: 1 byte (8 bits)
     * --------------------
     *  Padding with 0's.
     *
     */
    u_int8_t mbz;

    /*
     *
     * Field: Protocol
     * Size: 1 byte (8 bits)
     * --------------------
     *  Protocol of the packet.
     *
     */
    u_int8_t ptcl;

    /*
     *
     * Field: Total length
     * Size: 2 bytes (16 bits)
     * --------------------
     *  Total length of the packet.
     *
     */
    u_int16_t tcpl;

    /*
     *
     * Field: TCP header
     * Size: 20 bytes (5 words)
     * --------------------
     *  The original TCP header itself.
     *
    */
    struct tcphdr tcp;

    /*
     *
     * Field: Payload
     * Size: 1452 bytes (363 words)
     * --------------------
     *  The payload of the packet.
     *
    */
    char payload[MTU - 48];
};

/*
 * Struct: UDP pseudo header
 * Size: 12 bytes (3 words)
 * --------------------
 *  A pesudo header of UDP packet, used to calculate packet's checksum.
 * 
*/
struct pseudo_udp
{
    /*
     *
     * Field: Source IPv4 address
     * Size: 4 bytes (32 bits)
     * --------------------
     *  The source IP address of the packet.
     *
     */
    u_int32_t source_address;

    /*
     *
     * Field: Destenation IPv4 address
     * Size: 4 bytes (32 bits)
     * --------------------
     *  The destenation IP address of the packet.
     *
     */
    u_int32_t dest_address;

    /*
     *
     * Field: Padding
     * Size: 1 byte (8 bits)
     * --------------------
     *  Padding with 0's.
     *
     */
    u_int8_t placeholder;

    /*
     *
     * Field: Protocol
     * Size: 1 byte (8 bits)
     * --------------------
     *  Protocol of the packet.
     *
     */
    u_int8_t protocol;

    /*
     *
     * Field: Total length
     * Size: 2 bytes (16 bits)
     * --------------------
     *  Total length of the packet.
     *
     */
    u_int16_t udp_length;
};


/****************************************/
/*************** Functions **************/
/****************************************/

/*
 * Function:  packetSniffer
 * --------------------
 * A sniffing packet function, using the PCAP library.
 *
 *  args: arguments.
 *
 *  header: the pcap header of the packet.
 * 
 *  packet: the packet itself.
 * 
 */
void packetSniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*
 * Function:  packetSniffer
 * --------------------
 * A sniffing packet function, using the PCAP library.
 *
 *  args: arguments.
 *
 *  header: the pcap header of the packet.
 * 
 *  packet: the packet itself.
 * 
 */
void send_raw_ip_packet(struct ip *iph);

/*
 * Function:  in_cksum
 * --------------------
 * Calculates ICMP header checksum.
 *
 *  buf: pointer to the start of the header.
 *
 *  length: packet length.
 * 
 *  return: unsigned 16 bits number that represents the
 *              calculated ICMP checksum.
 * 
 */
unsigned short in_cksum(unsigned short *buf, int length);

/*
 * Function:  calculate_tcp_checksum
 * --------------------
 * Calculates TCP header checksum using pesudo header.
 *
 *  iph: a pointer to the start of the packet.
 * 
 *  return: unsigned 16 bits number that represents the
 *              calculated TCP checksum.
 * 
 */
unsigned short calculate_tcp_checksum(struct ip *iph);

/*
 * Function:  csum
 * --------------------
 * Calculates UDP header checksum using pesudo header.
 *
 *  ptr: pointer to the start of the header.
 *
 *  nbytes: packet length.
 * 
 *  return: unsigned 16 bits number that represents the
 *              calculated UDP checksum.
 * 
 */
unsigned short csum(unsigned short *ptr, int nbytes);

/*
 * Function:  spoofICMP
 * --------------------
 * Spoof a ICMP packet.
 *
 *  iph: an ip header that contains all paraments to setup
 *          an ICMP packet.
 * 
 */
void spoofICMP(struct ip *iph);

/*
 * Function:  spoofTCP
 * --------------------
 * Spoof a TCP packet.
 *
 *  iph: an ip header that contains all paraments to setup
 *          a TCP packet.
 * 
 */
void spoofTCP(struct ip *iph);

/*
 * Function:  spoofUDP
 * --------------------
 * Spoof a UDP packet.
 *
 *  iph: an ip header that contains all paraments to setup
 *          an UDP packet.
 * 
 */
void spoofUDP(struct ip *iph);

#endif