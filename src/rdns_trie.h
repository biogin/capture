
#ifndef CAPTURE_RDNS_TRIE_H
#define CAPTURE_RDNS_TRIE_H

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

// reverse dns lookup cache table using trie

#define MAX_NUM_IP_CHARS 11 // 0-9 and .

typedef struct rdns_node {
    char url[NI_MAXHOST];
    int isEndWord;

    struct rdns_node* nodes[MAX_NUM_IP_CHARS];
} rdns_node;

void insert_ip(struct rdns_node* root, const u_char* ipadr, char host[NI_MAXHOST]);
int get_hostname(struct rdns_node* root, const u_char* ipadr, char host[NI_MAXHOST]);
int has_ip(void* trie, u_int32_t ipadr);

void init_rdns_trie(struct rdns_node* root);

void del_rdns_trie(struct rdns_node* root); // recursive free

#endif //CAPTURE_RDNS_TRIE_H
