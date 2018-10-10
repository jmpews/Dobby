#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "interceptor.h"
#include "memory_manager.h"
#include "std_kit/std_list.h"

interceptor_t *g_interceptor = NULL;
interceptor_t *interceptor_cclass(shared_instance)(void) {
  if (g_interceptor == NULL) {
    g_interceptor                 = SAFE_MALLOC_TYPE(interceptor_t);
    g_interceptor->hook_entries   = list_new();
    g_interceptor->memory_manager = memory_manager_cclass(shared_instance)();
  }
  return g_interceptor;
}

hook_entry_t *interceptor_cclass(find_hook_entry)(interceptor_t *self, void *target_address) {
  if (!self)
    self = interceptor_cclass(shared_instance)();

  list_iterator_t *it = list_iterator_new(self->hook_entries, LIST_HEAD);
  for (int i = 0; i < self->hook_entries->len; i++) {
    hook_entry_t *entry = (hook_entry_t *)(list_at(self->hook_entries, i)->val);
    if (entry->target_address == target_address) {
      return entry;
    }
  }
  return NULL;
}

void interceptor_cclass(add_hook_entry)(interceptor_t *self, hook_entry_t *entry) {
  list_rpush(self->hook_entries, list_node_new(entry));
  return;
}