#ifndef STD_LIST_H
#define STD_LIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { LIST_HEAD, LIST_TAIL } list_direction_t;

typedef struct list_node {
  struct list_node *prev;
  struct list_node *next;
  void *val;
} list_node_t;

typedef struct {
  list_node_t *head;
  list_node_t *tail;
  unsigned int len;
  void (*free)(void *val);
  int (*match)(void *a, void *b);
} list_t;

typedef struct {
  list_node_t *next;
  list_direction_t direction;
} list_iterator_t;

// list_node_t
list_node_t *list_node_new(void *val);

// list_t
list_t *list_new();

list_node_t *list_rpush(list_t *self, list_node_t *node);

list_node_t *list_lpush(list_t *self, list_node_t *node);

list_node_t *list_find(list_t *self, void *val);

list_node_t *list_at(list_t *self, int index);

list_node_t *list_rpop(list_t *self);

list_node_t *list_lpop(list_t *self);

void list_remove(list_t *self, list_node_t *node);

void list_destroy(list_t *self);

// llist_iterator_t
list_iterator_t *list_iterator_new(list_t *list, list_direction_t direction);

list_iterator_t *list_iterator_new_from_node(list_node_t *node, list_direction_t direction);

list_node_t *list_iterator_next(list_iterator_t *self);

void list_iterator_destroy(list_iterator_t *self);

#ifdef __cplusplus
}
#endif

#endif // !STD_LIST_H
