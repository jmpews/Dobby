#include "closure_bridge.h"
#include "memory_manager.h"

ClosureBridge *gClosureBridge = NULL;
ClosureBridge *ClosureBridgeCClass(SharedInstance)() {
  if (gClosureBridge == NULL) {
    gClosureBridge                    = SAFE_MALLOC_TYPE(ClosureBridge);
    gClosureBridge->trampolines       = list_new();
    gClosureBridge->trampoline_tables = list_new();
  }
  return gClosureBridge;
}

ClosureTrampolineTable *ClosureBridgeCClass(AllocateClosureTrampolineTable)(ClosureBridge *self) {
  void *mmap_page = NULL;
  long page_size  = 0;

  memory_manager_t *memory_manager = memory_manager_cclass(shared_instance)();
  void *page_ptr                   = memory_manager_cclass(allocate_page)(memory_manager, PROT_R_X, 1);

  ClosureTrampolineTable *table = SAFE_MALLOC_TYPE(ClosureTrampolineTable);

  ClosureBridgeCClass(InitializeTablePage)(table, page_ptr);

  list_rpush(self->trampoline_tables, list_node_new(table));

  return table;
}

ClosureTrampolineEntry *ClosureBridgeCClass(CreateClosureTrampoline)(ClosureBridge *self, void *carry_data,
                                                                     void *forward_code) {
  ClosureTrampolineEntry *entry = NULL;
  ClosureTrampolineTable *table   = NULL;

  list_iterator_t *it = list_iterator_new(self->trampoline_tables, LIST_HEAD);
  for (int i = 0; i < self->trampoline_tables->len; i++) {
    ClosureTrampolineTable *tmp_table = (ClosureTrampolineTable *)(list_at(self->trampoline_tables, i)->val);
    if (tmp_table->free_count > 0) {
      table = tmp_table;
    }
  }

  if (!table) {
    table = ClosureBridgeCClass(AllocateClosureTrampolineTable)(self);
  }

  entry = SAFE_MALLOC_TYPE(ClosureTrampolineEntry);
  ClosureBridgeCClass(InitializeClosureTrampoline)(table, entry, carry_data, forward_code);

  list_rpush(self->trampolines, list_node_new(entry));
  return entry;
}
