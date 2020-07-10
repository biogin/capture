#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "rdns_trie.h"

// TODO Support for ip6 entries

static inline int get_char_index(char c) { return c == '.' ? 10 : c - '0'; }

static struct rdns_node* new_node() {
    struct rdns_node* n = malloc(sizeof(rdns_node));

    assert(n != NULL);

    n->isEndWord = 0;

    memset(n->url, 0, sizeof(n->url));
    memset(n->nodes, 0, sizeof(n->nodes));

    return n;
}

static int rdns_lookup(const char* ipaddr, char buf[NI_MAXHOST]) {
    struct sockaddr_in ip4;

    ip4.sin_port = htons(0);
    ip4.sin_family = AF_INET;

    inet_pton(AF_INET, ipaddr, &ip4.sin_addr);

    char host[NI_MAXHOST], service[NI_MAXSERV];

    int res = getnameinfo((struct sockaddr*)&ip4, sizeof(struct sockaddr_in), host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);

    if (res == 0) {
        strcpy(buf, host);

        return 0;
    }

    return 1;
}

void insert_ip(struct rdns_node* root, const u_char* ipaddr, char host[NI_MAXHOST]) {
    struct rdns_node* cur = root;
    int len = strlen(ipaddr) - 1, idx;

    // for each char walk up the trie and insert rdns_node if it doesn't already exist
    // and store resolved hostname in the last node
    /*  e.g for ip = 85.250.148.8 trie is gonna look like this
     *
     *                  8
     *                5
     *              .
     *             2
     *           5
     *         0
     *       ............. and up until the last char "8"
     *       8  <<<-   here we are storing hostname
     *
     */
    for (int i = 0; i < len; i++) {
        idx = get_char_index(ipaddr[i]);

        cur = cur->nodes[idx] == NULL ?
                (cur->nodes[idx] = new_node()) :
                cur->nodes[idx];
    }

    rdns_lookup(ipaddr, cur->url);
    cur->isEndWord = 1;

    strcpy(host, cur->url);
}

// 0 on successful hostname retrieval
// 1 otherwise
int get_hostname(struct rdns_node* root, const u_char* ipadr, char host[NI_MAXHOST]) {
    struct rdns_node* prev = root;
    int len = strlen(ipadr) - 1;

    for (int i = 0; i < len; i++) {
        struct rdns_node* cur = prev->nodes[get_char_index(ipadr[i])];

        if (cur == NULL)
            return 1;

        prev = cur;
    }

    strcpy(host, prev->url);

    return 0;
}

void init_rdns_trie(struct rdns_node* root) {
    root->isEndWord = 0;

    memset(root->nodes, 0, sizeof(root->nodes));
    memset(root->url, 0, sizeof(root->url));
}

void del_rdns_trie(struct rdns_node* root) {
    if (root == NULL) {
        return;
    }

    for (int i = 0, s = MAX_NUM_IP_CHARS; i < s; i++) {
        if (root->nodes[i] != NULL) {
            del_rdns_trie(root->nodes[i]);
            free(root->nodes[i]);
        }
    }
}
