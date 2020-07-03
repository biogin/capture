
#ifndef CAPTURE_CONNECTION_H
#define CAPTURE_CONNECTION_H

#include <netinet/in.h>
#include <netinet/tcp.h>

#define INITIAL_BUCKETS_SIZE 250

typedef struct connection {
   u_char ip[15];
   uint16_t port;

   struct connection* remote_host;
   struct tcphdr tcp_headers;
} connection;

typedef struct conn_node {
    u_char key[21];
    connection* conn;

    struct conn_node* next;
} conn_node;

typedef struct connections_map {
    int size;
    int capacity;
    double load_factor;

    conn_node* buckets[INITIAL_BUCKETS_SIZE];
} connections_map;

conn_node* get_connection(const connections_map*, const connection*);
conn_node* insert_connection(connections_map*, connection*);
int delete_connection(const connections_map* m, const connection*);

#endif //CAPTURE_CONNECTION_H
