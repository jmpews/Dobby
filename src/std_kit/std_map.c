/** 
 * Copyright (c) 2014 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include "std_map.h"
#include <stdlib.h>
#include <string.h>

static unsigned map_hash(const char *str) {
    unsigned hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) ^ *str++;
    }
    return hash;
}

static map_node_t *map_node_new(const char *key, map_value_t value) {
    map_node_t *node;

    int key_str_len = strlen(key) + 1;
    node            = (map_node_t *)malloc(sizeof(map_node_t) + key_str_len);

    node->hash  = map_hash(key);
    node->value = value;

    // copy key string append the map_node_t
    memcpy(node + 1, key, key_str_len);
    return node;
}

static int map_bucket_index(map_base_t *m, unsigned hash) {
    /* If the implementation is changed to allow a non-power-of-2 bucket count,
   * the line below should be changed to use mod instead of AND */
    return hash & (m->nbuckets - 1);
}

static void map_add_node(map_base_t *m, map_node_t *node) {
    int n         = map_bucket_index(m, node->hash);
    node->next    = m->buckets[n];
    m->buckets[n] = node;
}

static int map_resize(map_base_t *m, int nbuckets) {
    map_node_t *nodes, *node, *next;
    map_node_t **buckets;
    int i;
    /* Chain all nodes together */
    nodes = NULL;
    i     = m->nbuckets;
    while (i--) {
        node = (m->buckets)[i];
        while (node) {
            next       = node->next;
            node->next = nodes;
            nodes      = node;
            node       = next;
        }
    }
    /* Reset buckets */
    buckets = realloc(m->buckets, sizeof(*m->buckets) * nbuckets);
    if (buckets != NULL) {
        m->buckets  = buckets;
        m->nbuckets = nbuckets;
    }
    if (m->buckets) {
        memset(m->buckets, 0, sizeof(*m->buckets) * m->nbuckets);
        /* Re-add nodes to buckets */
        node = nodes;
        while (node) {
            next = node->next;
            map_add_node(m, node);
            node = next;
        }
    }
    /* Return error code if realloc() failed */
    return (buckets == NULL) ? -1 : 0;
}

static map_node_t *map_get_node(map_base_t *m, const char *key) {
    unsigned hash = map_hash(key);
    map_node_t **next;
    if (m->nbuckets > 0) {
        next = &m->buckets[map_bucket_index(m, hash)];
        while (*next) {
            if ((*next)->hash == hash && !strcmp((char *)(*next + 1), key)) {
                return *next;
            }
            next = &(*next)->next;
        }
    }
    return NULL;
}

map_value_t map_get_value(map_base_t *m, const char *key) {
    map_node_t *node;
    node = map_get_node(m, key);
    if (node)
        return node->value;
    return (map_value_t){0};
}

map_base_t *map_new() {
    map_base_t *map = (map_base_t *)malloc(sizeof(map_base_t));
    memset(map, 0, sizeof(map_base_t));
    return map;
}

void map_destory(map_base_t *m) {
    map_node_t *next, *node;
    int i;
    i = m->nbuckets;
    while (i--) {
        node = m->buckets[i];
        while (node) {
            next = node->next;
            free(node);
            node = next;
        }
    }
    free(m->buckets);
}

int map_set_value(map_base_t *m, const char *key, map_value_t value) {
    int n, err;
    map_node_t *node;

    map_value_t tmp_value;

    /* Find & replace existing node */
    node = map_get_node(m, key);
    if (node) {
        node->value = value;
        return 0;
    }
    /* Add new node */
    node = map_node_new(key, value);
    if (node == NULL)
        goto fail;
    if (m->nnodes >= m->nbuckets) {
        n   = (m->nbuckets > 0) ? (m->nbuckets << 1) : 1;
        err = map_resize(m, n);
        if (err)
            goto fail;
    }
    map_add_node(m, node);
    m->nnodes++;
    return 0;
fail:
    if (node)
        free(node);
    return -1;
}

void map_remove_value(map_base_t *m, const char *key) {

    unsigned hash = map_hash(key);
    map_node_t **next;
    map_node_t *node;
    if (m->nbuckets > 0) {
        next = &m->buckets[map_bucket_index(m, hash)];
        while (*next) {
            if ((*next)->hash == hash && !strcmp((char *)(*next + 1), key)) {
                node  = *next;
                *next = (*next)->next;
                free(node);
                m->nnodes--;
            }
            next = &(*next)->next;
        }
    }
}

map_iter_t map_iter_new(void) {
    map_iter_t iter;
    iter.bucket_index = -1;
    iter.node_next    = NULL;
    return iter;
}

map_node_t *map_iter_next(map_base_t *m, map_iter_t *iter) {

    map_node_t *iter_node;

    for (int i = iter->bucket_index; i < m->nbuckets; i++) {
        if (iter->node_next)
            iter_node = iter->node_next;
        else
            iter_node = m->buckets[i];
        while (iter_node->next) {
            iter->node_next    = iter_node->next;
            iter->bucket_index = i;
            return iter->node_next;
        }
    }
    return NULL;
}
