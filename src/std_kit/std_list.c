
#include "std_list.h"

// list_t
list_t *list_new() {
    list_t *self;
    if (!(self = malloc(sizeof(list_t))))
        return NULL;
    self->head  = NULL;
    self->tail  = NULL;
    self->free  = NULL;
    self->match = NULL;
    self->len   = 0;
    return self;
}

void list_destroy(list_t *self) {
    unsigned int len = self->len;
    list_node_t *next;
    list_node_t *curr = self->head;

    while (len--) {
        next = curr->next;
        if (self->free)
            self->free(curr->val);
        free(curr);
        curr = next;
    }

    free(self);
}

list_node_t *list_rpush(list_t *self, list_node_t *node) {
    if (!node)
        return NULL;

    if (self->len) {
        node->prev       = self->tail;
        node->next       = NULL;
        self->tail->next = node;
        self->tail       = node;
    } else {
        self->head = self->tail = node;
        node->prev = node->next = NULL;
    }

    ++self->len;
    return node;
}

list_node_t *list_rpop(list_t *self) {
    if (!self->len)
        return NULL;

    list_node_t *node = self->tail;

    if (--self->len) {
        (self->tail = node->prev)->next = NULL;
    } else {
        self->tail = self->head = NULL;
    }

    node->next = node->prev = NULL;
    return node;
}

list_node_t *list_lpop(list_t *self) {
    if (!self->len)
        return NULL;

    list_node_t *node = self->head;

    if (--self->len) {
        (self->head = node->next)->prev = NULL;
    } else {
        self->head = self->tail = NULL;
    }

    node->next = node->prev = NULL;
    return node;
}

list_node_t *list_lpush(list_t *self, list_node_t *node) {
    if (!node)
        return NULL;

    if (self->len) {
        node->next       = self->head;
        node->prev       = NULL;
        self->head->prev = node;
        self->head       = node;
    } else {
        self->head = self->tail = node;
        node->prev = node->next = NULL;
    }

    ++self->len;
    return node;
}

list_node_t *list_find(list_t *self, void *val) {
    list_iterator_t *it = list_iterator_new(self, LIST_HEAD);
    list_node_t *node;

    while ((node = list_iterator_next(it))) {
        if (self->match) {
            if (self->match(val, node->val)) {
                list_iterator_destroy(it);
                return node;
            }
        } else {
            if (val == node->val) {
                list_iterator_destroy(it);
                return node;
            }
        }
    }

    list_iterator_destroy(it);
    return NULL;
}

list_node_t *list_at(list_t *self, int index) {
    list_direction_t direction = LIST_HEAD;

    if (index < 0) {
        direction = LIST_TAIL;
        index     = ~index;
    }

    if ((unsigned)index < self->len) {
        list_iterator_t *it = list_iterator_new(self, direction);
        list_node_t *node   = list_iterator_next(it);
        while (index--)
            node = list_iterator_next(it);
        list_iterator_destroy(it);
        return node;
    }

    return NULL;
}

void list_remove(list_t *self, list_node_t *node) {
    node->prev ? (node->prev->next = node->next) : (self->head = node->next);

    node->next ? (node->next->prev = node->prev) : (self->tail = node->prev);

    if (self->free)
        self->free(node->val);

    free(node);
    --self->len;
}

// list_node_t
list_node_t *list_node_new(void *val) {
    list_node_t *self;
    if (!(self = malloc(sizeof(list_node_t))))
        return NULL;
    self->prev = NULL;
    self->next = NULL;
    self->val  = val;
    return self;
}

// list_iterator_t
list_iterator_t *list_iterator_new(list_t *list, list_direction_t direction) {
    list_node_t *node = direction == LIST_HEAD ? list->head : list->tail;
    return list_iterator_new_from_node(node, direction);
}

list_iterator_t *list_iterator_new_from_node(list_node_t *node, list_direction_t direction) {
    list_iterator_t *self;
    if (!(self = malloc(sizeof(list_iterator_t))))
        return NULL;
    self->next      = node;
    self->direction = direction;
    return self;
}

list_node_t *list_iterator_next(list_iterator_t *self) {
    list_node_t *curr = self->next;
    if (curr) {
        self->next = self->direction == LIST_HEAD ? curr->next : curr->prev;
    }
    return curr;
}

void list_iterator_destroy(list_iterator_t *self) {
    free(self);
    self = NULL;
}
