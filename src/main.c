#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include "process_packet.h"

#define MAX_NUMBER_OF_IFS 100
#define PACKET_BUF_TIMEOUT 300

#define AVAILABLE_OPTIONS "lptuie:n:"
/*
     * n(name) interface name
     * l(list) list all the available ifs and choose one to sniff on
     * p(promisc) enable promisc mode
     * t,u,i(tcp,udp,icmp) only show specific 4L packets
 */

void print_header() {}

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
    pcap_handler

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

   print_header();

    printf("Starting to capture on %s\n", interface);
    printf("Layer");

    setbuf(stdout, NULL); // print packets immediately

    pcap_loop(handle, -1, process_packet, NULL);

    return 0;
}
