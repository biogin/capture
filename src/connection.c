#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>

#include "connection.h"

static const char *itoa(int val, int base); // not a C standard so have to implement it

static int get_connection_hash(const connections_map *m, u_char* key);
static void get_connection_key(const connection *conn, u_char* buf);

unsigned long hash(u_char *str) {
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static int get_connection_hash(const connections_map *m, u_char* key) {
    return hash(key) % m->capacity;
}

static void get_connection_key(const connection *conn, u_char* buf) {
    // "key" for a map's gonna look like:  192.168.0.1:4205 (for example)
    strncpy(buf, conn->ip, 15);
    strcat(buf, ":");
    strcat(buf, itoa(conn->port, 10));
}

static const char *itoa(int val, int base) {
    static char buf[32] = {0};

    int i = 30;

    for (; val && i; i--, val /= base)
        buf[i] = "0123456789abcdef"[val % base];

    return &buf[i + 1];
}

conn_node *insert_connection(connections_map *map, connection *conn) {
    u_char buf[21];
    get_connection_key(conn, buf);
    map->size++;
    int hash = get_connection_hash(map, buf);

    conn_node *c = map->buckets[hash];

    if (c == NULL) {
        c = malloc(sizeof(*conn));

        assert(c != NULL);

        c->next = NULL;
        c->conn = conn;

        memset(c->key, '\0', sizeof(c->key));
        strcpy(c->key, buf);

        return (map->buckets[hash] = c);
    }

    while (true) {
        if (strcmp(c->key, buf) == 0) {
            // TODO Append all incoming tcp headers to "conn" and return it

            return c;
        }

        if (c->next == NULL) {
            conn_node* new_connection = malloc(sizeof(conn));

            new_connection->next = NULL;
            new_connection->conn = conn;
            memset(new_connection->key, '\0', sizeof(new_connection->key));
            strcpy(new_connection->key, buf);

            return (c->next = new_connection);
        }

        c = c->next;
    }
}

conn_node *get_connection(const connections_map *map, const connection *conn) {
    u_char buf[21];
    get_connection_key(conn, buf);
    int hash = get_connection_hash(map, buf);

    conn_node *dumb = map->buckets[hash];

    while (dumb != NULL && strcmp(dumb->key, buf) != 0) {
        dumb = dumb->next;
    }

    return dumb;
}
