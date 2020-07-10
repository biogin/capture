#include <stdio.h>
#include <string.h>

#include <inttypes.h>

#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netdb.h>

#include "connection.h"
#include "rdns_trie.h"

void print_eth_hdr(const struct ether_header *);

void process_ipv4(const u_char *);

void process_ipv6(); // TODO
void process_arp(const u_char *); // TODO

void process_tcp(const u_char *tcp_buf, int ip_header_size);

void process_udp(const u_char *payload, uint16_t len);

void process_icmp(const u_char *payload, uint16_t iphdr_len);

void print_ipv4_hdr(const struct iphdr *);

void print_tcp_headers(const struct tcphdr *, uint16_t, uint16_t);

void print_data(const u_char *buffer, const u_int32_t len); // TODO

void reset_color() {
    printf("\033[0m");
}

void set_stdout_color(const char *color) {
    printf("\033%s", color);
}

void print_char(const char *c, int n) {
    for (int i = 0; i < n; ++i) {
        printf("%s", c);
    }
}

FILE *logfile; // TODO
struct sockaddr_in source, dest;
u_char sip[16], dip[16];

extern connections_map map;
extern rdns_node root;

void process_packet(u_char *_, const struct pcap_pkthdr *hdr, const u_char *buffer) {
    const struct ether_header *eth_ptr = (struct ether_header *) (buffer);
    const u_char *payload = (ETHER_HDR_LEN + buffer);
    const uint16_t type = ntohs(eth_ptr->ether_type);

    print_eth_hdr(eth_ptr);

    switch (type) {
        case ETHERTYPE_IP:
            process_ipv4(payload);
            break;
        case ETHERTYPE_ARP:
            process_arp(payload);
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

void print_eth_hdr(const struct ether_header *hdr) {
    printf(" ------\n");
    printf("  2L  |  ETH: MAC(");
    set_stdout_color("[0;34m");; // blue
    printf("%s ", ether_ntoa((struct ether_addr *) hdr->ether_shost));
    reset_color();
    printf("--> ");
    set_stdout_color("[0;34m");
    printf("%s", ether_ntoa((struct ether_addr *) hdr->ether_dhost));
    reset_color();
    printf(")");

    print_char(" ", 20);
    printf("\n");
}

void process_ipv4(const u_char *packet) {
    struct iphdr *ip_hdr = (struct iphdr *) (packet);
    unsigned int hdr_size = ip_hdr->ihl * 4;
    const u_char *payload = packet + hdr_size;

    print_ipv4_hdr(ip_hdr);

    switch (ip_hdr->protocol) {
        case IPPROTO_ICMP:
            process_icmp(payload, ip_hdr->tot_len);
            break;
        case IPPROTO_TCP:
            process_tcp(payload, ip_hdr->tot_len);
            break;
        case IPPROTO_UDP:
            process_udp(payload, ip_hdr->tot_len);
            break;
        default:
            break;
    }
}

void process_arp(const u_char *packet) {
    struct arphdr *arp = (struct arphdr *) (packet);

    printf("      |  ARP: %s\n",
           arp->ar_op == ARPOP_REQUEST ? "BROADCAST" :
           arp->ar_op == ARPOP_REPLY ? "REPLY" :
           arp->ar_op == ARPOP_NAK ? "NAK" :
           arp->ar_op == ARPOP_RREQUEST ? "RARP BROADCAST" :
           arp->ar_op == ARPOP_RREPLY ? "RARP REPLY" : "UNKNOWN"
    );
}

void print_ipv4_hdr(const struct iphdr *hdr) {
    static int count = 0;
    char shost[NI_MAXHOST];
    char dhost[NI_MAXHOST];
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = hdr->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = hdr->daddr;

    strcpy(sip, inet_ntoa(source.sin_addr));
    strcpy(dip, inet_ntoa(dest.sin_addr));

    // TODO check -r flag for not resolving hosts
//  if (-r flag is set) {
    if (get_hostname(&root, sip, shost) == 1) {
        insert_ip(&root, sip, shost);
    }

    if (get_hostname(&root, dip, dhost) == 1) {
        insert_ip(&root, dip, dhost);
    }
//    }

    printf("  3L  |  IP4: host(%s --> %s)", shost, dhost);
    printf("  ip(%s --> %s)", sip, dip);
    print_char(" ", 20);
    printf("\n");
}

void process_tcp(const u_char *tcp_buf, int ip_header_size) {
    struct tcphdr *tcp = (struct tcphdr *) tcp_buf;
    const u_char *payload = (tcp_buf + tcp->th_off * 4);
    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);
    connection local;
    connection remote;

    strcpy(local.ip, sip);
    strcpy(remote.ip, dip);

    local.port = sport;
    remote.port = dport;

    local.remote_host = &remote;

//    conn_node* local_connection_entry = get_connection(&map, &local);
//    conn_node* local_remote_connection_entry = get_connection(&map, &remote);
//
//    if (local_connection_entry != NULL) {
//        1r
//
//    } else if (local_remote_connection_entry != NULL) {
//
//    } else {
//
//        insert_connection(&map, &local);
//
//        local_connection_entry = get_connection(&map, &local);
//
//        printf("\nconnection: %d    %s\n", local_connection_entry->conn->port, local_connection_entry->key);
//    }

    print_tcp_headers(tcp, sport, dport);
}

void print_tcp_headers(const struct tcphdr *tcp, uint16_t sport, uint16_t dport) {
    printf("  4L  |  TCP: port(%d -> %d)  ", sport, dport);
    // TODO Print relative seq and ack nums
    printf("seq=");
    printf("%" PRIu32, ntohl(tcp->th_seq));
    printf(" ack=");
    printf("%" PRIu32, ntohl(tcp->th_ack));
    printf("  [CWR=%d, ECN-Echo=%d, URG=%d, ACK=%d, PSH=%d, RST=%d, SYN=%d, FIN=%d]  ",
           (tcp->th_flags & 8) ? 1 : 0,
           (tcp->th_flags & 9) ? 1 : 0,
           (unsigned int) tcp->urg,
           (unsigned int) tcp->ack,
           (unsigned int) tcp->psh,
           (unsigned int) tcp->rst,
           (unsigned int) tcp->syn,
           (unsigned int) tcp->fin
    );
    printf("win=%d  ", ntohs(tcp->window));
    printf("checksum=%d\n", ntohs(tcp->check));

//    print_data(payload, ip_header_size);

    printf(" ------\n");
}

void process_udp(const u_char *payload, uint16_t _) {
    struct udphdr *udp = (struct udphdr *) (payload);

    printf("  4L  |  UDP: port(%d -> %d)  checksum=%d\n",
           ntohs(udp->uh_sport),
           ntohs(udp->uh_dport),
           ntohs(udp->check));
//    print_data(payload, ip_header_size);

    printf(" ------\n");
}

void process_icmp(const u_char *payload, uint16_t _) {
    struct icmphdr *icmp = (struct icmphdr *) (payload);

    printf("  4L  |  ICMP: type=%d  code=%d  checksum=%d\n",
           icmp->type,
           icmp->code,
           ntohs(icmp->checksum)
    );
//    print_data(payload, ip_header_size);

    printf(" ------\n");
}

// thx stackoverflow
void print_data(const u_char *data_buffer, const u_int32_t length) {

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
