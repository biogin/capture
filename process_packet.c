#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>

void process_ipv4(const struct ip*);
void process_arp(const struct arphdr*); // TODO
void process_ipv6(); // TODO

void process_packet(u_char* _, const struct pcap_pkthdr* hdr, const u_char* packet) {
    const struct ether_header *eth_ptr = (struct ether_header*)(packet);
    uint16_t type = ntohs(eth_ptr->ether_type);
    const u_char* payload = (ETHER_HDR_LEN + packet);

    switch (type) {
        case ETHERTYPE_IP:
            process_ipv4((const struct ip*)payload);
            break;
        case ETHERTYPE_ARP:
              printf("Nope\n");
//            process_arp(ETH_HLEN + packet);
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
}

void process_ipv4(const struct ip* packet) {
    printf("Total packet length %d  |  ", packet->ip_len);
    printf("%s -----> %s\n", inet_ntoa(packet->ip_src), inet_ntoa(packet->ip_dst));

}
