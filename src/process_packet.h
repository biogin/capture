#ifndef CAPTURE_PROCESS_PACKET_H
#define CAPTURE_PROCESS_PACKET_H

void process_packet(u_char* _, const struct pcap_pkthdr* hdr, const u_char* packet);

#endif //CAPTURE_PROCESS_PACKET_H
