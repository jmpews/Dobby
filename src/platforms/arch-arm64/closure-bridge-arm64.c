#include "closure_bridge.h"
#include "core.h"
#include "memory_manager.h"

#define closure_bridge_trampoline_template_length (7 * 4)

void ClosureBridgeCClass(InitializeTablePage)(ClosureTrampolineTable *table, void *page_address) {
  memory_manager_t *memory_manager = memory_manager_cclass(shared_instance)();
  memory_manager_cclass(set_page_permission)(page_address, PROT_RW_, 1);

  int page_size = memory_manager_cclass(get_page_size)();

  int t              = page_size / closure_bridge_trampoline_template_length;
  void *copy_address = page_address;
  for (int i = 0; i < t; ++i) {
    copy_address = (void *)((intptr_t)page_address + i * closure_bridge_trampoline_template_length);
    memcpy(copy_address, (void *)closure_bridge_trampoline_template, closure_bridge_trampoline_template_length);
  }

  memory_manager_cclass(set_page_permission)(page_address, PROT_R_X, 1);

  table->entry           = page_address;
  table->trampoline_page = page_address;
  table->used_count      = 0;
  table->free_count      = (uint16_t)t;
}

void ClosureBridgeCClass(InitializeClosureTrampoline)(ClosureTrampolineTable *table, ClosureTrampolineEntry *entry,
                                                      void *carry_data, void *forward_code) {
  assert(entry);
  assert(table);
  uint16_t trampoline_used_count = table->used_count;
  void *address =
      (void *)((intptr_t)table->trampoline_page + closure_bridge_trampoline_template_length * trampoline_used_count);

  entry->forward_code           = forward_code;
  entry->carry_data           = carry_data;
  entry->address = address;

  table->used_count++;
  table->free_count--;

  memory_manager_cclass(set_page_permission)(table->trampoline_page, PROT_RW_, 1);

  // bind data to trampline
  void *tmp = (void *)((intptr_t)entry->address + 4 * 3);
  memcpy(tmp, &entry, sizeof(ClosureTrampolineEntry *));

  // set trampoline to bridge
  void *tmpX = (void *)closure_bridge_template;
  tmp        = (void *)((intptr_t)entry->address + 4 * 5);
  memcpy(tmp, &tmpX, sizeof(void *));

  memory_manager_cclass(set_page_permission)(table->trampoline_page, PROT_R_X, 1);
}
