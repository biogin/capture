#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "connection.h"
#include "process_packet.h"
#include "rdns_trie.h"

#define MAX_NUMBER_OF_IFS 10
#define PACKET_BUF_TIMEOUT 300

#define AVAILABLE_OPTIONS "lptuie:n:"
/*
     * n(name) interface name
     * l(list) list all the available ifs and choose one to sniff on
     * p(promisc) enable promisc mode
     * t,u,i(tcp,udp,icmp) only show specific 4L packets
 */

connections_map map;
rdns_node root;

void sig_handler(int sig) {
    if (sig == SIGINT) {

        for (int i = 0, s = map.size; i < s; i++) {
            free(map.buckets[i]);
        }

        del_rdns_trie(&root);
    }
}

int if_is_up(u_char* interface) { // FIXME Bad file descriptor errno
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_RAW, 0);

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
        perror("SIOCGIFFLAGS");

    close(sock);

    return (ifr.ifr_flags & IFF_RUNNING) != 0;
}

int main(int argc, char* argv[]) {
    pcap_if_t* dvcs;
    pcap_t* handle;
    int c;
    char* interface = NULL;
    int dvcount = 0;
    int cnt; // TODO
    char list_interfaces = 0;
    char promisc = 0;
    char tcp = 1,
         udp = 0,
         icmp = 0;
    char interfaces[MAX_NUMBER_OF_IFS][50];
    char errbuf[PCAP_ERRBUF_SIZE];

    opterr = 0;

    while ((c = getopt(argc, argv, AVAILABLE_OPTIONS)) != -1) {
        switch (c) {
            case 'n':
                interface = optarg;
                break;
            case 'l':
                list_interfaces = 1;
                break;
            case 'p':
                promisc = 1;
                break;
            case 'c':
                cnt = optarg;
                break;
            case 't':
                tcp = 1;
                break;
            case 'u':
                udp = 1;
            case '?':
                break;
        }
    }

    if (pcap_findalldevs(&dvcs, errbuf) == -1) {
        printf("%s", errbuf);
        exit(1);
    }

    while (dvcs != NULL) {
        strcpy(interfaces[dvcount], dvcs->name);
        dvcs = dvcs->next;
        dvcount++;
    }

    if (list_interfaces) {
        int if_num;
        for (int i = 0; i < dvcount; ++i) {
            printf("%d. %s\n", i + 1, interfaces[i]);

//            if (if_is_up(interfaces[i]))
//                printf(" [UP, RUNNING]\n");
//            else
//                printf(" [DOWN]\n");
        }

        printf("Choose an interface to sniff on:\n");
        scanf("%d", &if_num);

        if (if_num > dvcount || if_num <= 0) {
            fprintf(stderr, "Invalid interface number %d. Provide one from the list above or use [-n] option to specify interface by name", if_num);
            exit(1);
        }

        interface = interfaces[if_num - 1];
    }

    if (interface == NULL) {
        interface = interfaces[0];
    }

   if ((handle = pcap_open_live(interface, 65000, promisc, PACKET_BUF_TIMEOUT, errbuf)) == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
       exit(1);
   }

    printf("Starting to capture on %s\n", interface);
    setbuf(stdout, NULL); // print packets immediately

    init_map(&map);
    init_rdns_trie(&root);

    pcap_loop(handle, -1, process_packet, NULL);

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        fprintf(stderr, "\ncan't catch SIGINT\n");

    return 0;
}
