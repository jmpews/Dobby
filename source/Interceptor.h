#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#include "dobby_internal.h"

// List utilty

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};
#define container_of(ptr, type, member)                                                                                \
  ({                                                                                                                   \
    const __typeof(((type *)0)->member) *__mptr = (ptr);                                                               \
    (type *)((char *)__mptr - offsetof(type, member));                                                                 \
  })

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define INIT_LIST_HEAD(ptr)                                                                                            \
  do {                                                                                                                 \
    (ptr)->next = (ptr);                                                                                               \
    (ptr)->prev = (ptr);                                                                                               \
  } while (0)

static inline int list_empty(struct list_head *head)
{
  return head->next == head;
}

static void __list_add(struct list_head *new_node, struct list_head *prev, struct list_head *next) {
  next->prev = new_node;
  new_node->next = next;
  new_node->prev = prev;
  prev->next = new_node;
}

static inline void list_add(struct list_head *new_node, struct list_head *head) {
  __list_add(new_node, head, head->next);
}

static inline void __list_del(struct list_head *prev, struct list_head *next) {
  next->prev = prev;
  prev->next = next;
}

static inline void list_del(struct list_head *entry) {
  __list_del(entry->prev, entry->next);
  entry->next = NULL;
  entry->prev = NULL;
}

typedef struct {
  struct list_head list;
  HookEntry info;
} HookEntryListNode;

class Interceptor {
public:
  static Interceptor *SharedInstance();

  HookEntry *FindHookEntry(void *address);

  void AddHookEntry(HookEntry *entry);

  void RemoveHookEntry(void *address);

  int GetHookEntryCount();

private:
  Interceptor() {
  }

  HookEntryListNode *FindHookEntryNode(void *address);

private:
  struct list_head hook_entry_list_;

  static Interceptor *priv_interceptor_;
};

#endif
