/** 
 * Copyright (c) 2014 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MAP_H
#define MAP_H

#include <string.h>

#define MAP_VERSION "0.1.0"

typedef union {
  int _int;
  float _float;
  double _double;
  void *_pointer;
} map_value_t;

typedef struct _map_node_t {
  unsigned hash;
  map_value_t value;
  struct _map_node_t *next;
} map_node_t;

typedef struct {
  map_node_t **buckets;
  unsigned nbuckets;
  unsigned nnodes;
} map_base_t, map_t;

typedef struct {
  unsigned bucket_index;
  map_node_t *node_next;
} map_iter_t;

map_base_t *map_new();

void map_destory(map_base_t *m);

map_value_t map_get_value(map_base_t *m, const char *key);

int map_set_value(map_base_t *m, const char *key, map_value_t value);

void map_remove_value(map_base_t *m, const char *key);

map_iter_t map_iter_new(void);

map_node_t *map_iter_next(map_base_t *m, map_iter_t *iter);
#endif
