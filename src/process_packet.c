#include <stdio.h>
#include <string.h>
#include <ncurses.h>

#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>

#include "utils/stdout.h"

void process_ipv4(const struct ip*);
void process_ipv6(); // TODO

void print_eth_hdr(const struct ether_header*);
void print_arp(const struct arphdr*); // TODO
void print_ipv4_hdr(const struct iphdr*);
void print_tcp(const struct tcp_hdr);

FILE* logfile;
struct sockaddr_in source, dest;

void process_packet(u_char* _, const struct pcap_pkthdr* hdr, const u_char* buffer) {
    const struct ether_header *eth_ptr = (struct ether_header*)(buffer);
    const u_char* payload = (ETHER_HDR_LEN + buffer);
    const uint16_t type = ntohs(eth_ptr->ether_type);

    print_eth_hdr(eth_ptr);

    switch (type) {
        case ETHERTYPE_IP:
            process_ipv4((const struct ip*)payload);
            break;
        case ETHERTYPE_ARP:
              printf("Nope\n");
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

void process_ipv4(const struct ip* packet) {
    unsigned int hdr_size = packet->ip_hl * 4;

    print_ipv4_hdr((struct iphdr *) (packet)); // just for clarity, i guess..

    switch (packet->ip_p) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_TCP:
            print
            break;
        case IPPROTO_UDP:
            break;
        default:
            break;
    }
}

void print_eth_hdr(const struct ether_header* hdr) {
    // ugly but who cares
    printf("\n");
    printf(" --------------------------------------------------------------\n");
    printf(" 2L ");

    printf("|  ETH: ");
    set_stdout_color("[0;34m");; // blue
    printf("%s ", ether_ntoa((struct ether_addr*)hdr->ether_shost));
    reset_color();
    printf("--> ");
    set_stdout_color("[0;34m");
    printf("%s", ether_ntoa((struct ether_addr*)hdr->ether_dhost));
    reset_color();

    print_char(" ", 20);
    printf("|\n");
}

void print_ipv4_hdr(const struct iphdr* hdr) {
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = hdr->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = hdr->daddr;

    printf(" 3L ");
    printf("|  IP: %s --> ", inet_ntoa(source.sin_addr));
    printf("%s", inet_ntoa(dest.sin_addr));
    print_char(" ", 20);
    printf("| \n");

    printf(" --------------------------------------------------------------");
    printf("\n");
}
