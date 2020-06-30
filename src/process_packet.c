#include <stdio.h>
#include <string.h>

#include <inttypes.h>

#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>

#include "utils/stdout.h"

void process_ipv4(const u_char*);
void process_ipv6(); // TODO

void print_eth_hdr(const struct ether_header*);
void print_arp(const struct arphdr*); // TODO
void print_ipv4_hdr(const struct iphdr*);
void print_tcp(const u_char*, const int);
void print_udp(const u_char*); // TODO

void print_data(const unsigned char *buffer, const unsigned int len); // TODO

FILE* logfile; // TODO
struct sockaddr_in source, dest;

void process_packet(u_char* _, const struct pcap_pkthdr* hdr, const u_char* buffer) {
    const struct ether_header *eth_ptr = (struct ether_header*)(buffer);
    const u_char* payload = (ETHER_HDR_LEN + buffer);
    const uint16_t type = ntohs(eth_ptr->ether_type);

    print_eth_hdr(eth_ptr);

    switch (type) {
        case ETHERTYPE_IP:
            process_ipv4(payload);
            break;
        case ETHERTYPE_ARP:
//            print_arp(ETH_HLEN + packet);
            break;
        case ETHERTYPE_REVARP:
            // TODO
            break;
        case ETHERTYPE_IPV6:
            // TODO
            break;
        default:
            printf("Currently there's no support for %d ether_type", type);
            return;
    }

//    printf("") // TODO print overall stats
}

void process_ipv4(const u_char* packet) {
    struct iphdr* ip_hdr = (struct iphdr*)(packet);
    unsigned int hdr_size = ip_hdr->ihl * 4;
    u_char* payload = packet + hdr_size;

    print_ipv4_hdr(ip_hdr);

    switch (ip_hdr->protocol) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_TCP:
            print_tcp(payload, hdr_size);
            break;
        case IPPROTO_UDP:
            break;
        default:
            break;
    }
}

void print_eth_hdr(const struct ether_header* hdr) {
    printf(" ------\n");
    printf("  2L  |  ETH: MAC(");
    set_stdout_color("[0;34m");; // blue
    printf("%s ", ether_ntoa((struct ether_addr*)hdr->ether_shost));
    reset_color();
    printf("--> ");
    set_stdout_color("[0;34m");
    printf("%s", ether_ntoa((struct ether_addr*)hdr->ether_dhost));
    reset_color();
    printf(")");

    print_char(" ", 20);
    printf("\n");
}

void print_ipv4_hdr(const struct iphdr* hdr) {
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = hdr->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = hdr->daddr;

    printf("  3L  |  IP4: ip(%s --> ", inet_ntoa(source.sin_addr));
    printf("%s)", inet_ntoa(dest.sin_addr));
    print_char(" ", 20);
    printf("\n");
}

void print_tcp(const u_char* tcp_buf, int ip_header_size) {
    struct tcphdr* tcp = (struct tcphdr*)tcp_buf;

    printf("  4L  |  TCP: port(%d ->", ntohs(tcp->th_sport));
    printf(" %d)  ", ntohs(tcp->th_dport));
    printf("seq=");
    printf("%" PRIu32, ntohl(tcp->th_seq));
    printf(" ack=");
    printf("%" PRIu32, ntohl(tcp->th_ack));
    printf("  [CWR=%d, ECN-Echo=%d, URG=%d, ACK=%d, PSH=%d, RST=%d, SYN=%d, FIN=%d]  ",
           (tcp->th_flags & 8) ? 1 : 0,
           (tcp->th_flags & 9) ? 1 : 0,
           (unsigned int)tcp->urg,
           (unsigned int)tcp->ack,
           (unsigned int)tcp->psh,
           (unsigned int)tcp->rst,
           (unsigned int)tcp->syn,
           (unsigned int)tcp->fin
    );
    printf("win=%d  ", ntohs(tcp->window));
    printf("checksum=%d", ntohs(tcp->check));
    printf("\n");

//    print_data(tcp) // TODO

    printf(" ------");
    printf("\n\n");
}

void print_data(const unsigned char *data_buffer, const unsigned int length) {

    printf("\t\tPayload: (%d bytes)\n\n", length - 32);
    unsigned char byte;
    unsigned int i, j;

    for (i = 0; i < length; i++) {
        byte = data_buffer[i];
        printf("%02x", data_buffer[i]);
        if (((i % 16) == 15) || (i == length - 1)) {
            for (j = 0; j < 15 - (i % 16); j++)
                printf("  ");
            printf("| ");
            for (j = (i - (i % 16)); j <= i; j++) {
                byte = data_buffer[j];
                if ((byte > 31) && (byte < 127))
                    printf("%c", byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}
