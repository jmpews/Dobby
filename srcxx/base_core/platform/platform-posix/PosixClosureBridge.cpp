//
// Created by jmpews on 2018/6/14.
//

#include "PosixClosureBridge.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define closure_bridge_trampoline_template_length (7 * 4)

ClosureTrampolineTable *ClosureBridge::allocateClosureTrampolineTable() {
  void *mmap_page;
  long page_size;
  page_size = sysconf(_SC_PAGESIZE);

  mmap_page = mmap(0, 1, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (mmap_page == MAP_FAILED) {
    // LOG-NEED
    return NULL;
  }

  if (mprotect(mmap_page, (size_t)page_size, (PROT_READ | PROT_WRITE))) {
    // LOG-NEED
    return NULL;
  }

  int t              = page_size / closure_bridge_trampoline_template_length;
  void *copy_address = mmap_page;
  for (int i = 0; i < t; ++i) {
    copy_address = (void *)((intptr_t)mmap_page + i * closure_bridge_trampoline_template_length);
    memcpy(copy_address, (void *)closure_bridge_trampoline_template, closure_bridge_trampoline_template_length);
  }

  if (mprotect(mmap_page, (size_t)page_size, (PROT_READ | PROT_EXEC))) {
    // LOG-NEED
    return NULL;
  }

  ClosureTrampolineTable *table = (ClosureTrampolineTable *)malloc(sizeof(ClosureTrampolineTable));
  table->entry                  = mmap_page;
  table->trampoline_page        = mmap_page;
  table->used_count             = 0;
  table->free_count             = (uint16_t)t;

  trampoline_tables.push_back(table);
  return table;
}

ClosureTrampolineEntry *ClosureBridge::CreateClosureTrampoline(void *carry_data, void *forward_code) {
  ClosureTrampolineEntry *cbi;
  ClosureTrampolineTable *table;
  long page_size = sysconf(_SC_PAGESIZE);

  for (auto tmpTable : trampoline_tables) {
    if (tmpTable->free_count > 0) {
      table = tmpTable;
      break;
    }
  }

  if (!table)
    table = allocateClosureTrampolineTable();

  uint16_t trampoline_used_count = table->used_count;
  void *address =
      (void *)((intptr_t)table->trampoline_page + closure_bridge_trampoline_template_length * trampoline_used_count);

  cbi               = new (ClosureTrampolineEntry);
  cbi->forward_code = forward_code;
  cbi->carry_data   = carry_data;
  cbi->address      = address;

  // bind data to trampline
  void *tmp = (void *)((intptr_t)cbi->address + 4 * 3);
  memcpy(tmp, &cbi, sizeof(ClosureTrampolineEntry *));

  // set trampoline to bridge
  void *tmpX = (void *)closure_bridge_template;
  tmp        = (void *)((intptr_t)cbi->address + 4 * 5);
  memcpy(tmp, &tmpX, sizeof(void *));

  if (mprotect(table->trampoline_page, (size_t)page_size, (PROT_READ | PROT_EXEC))) {
    // LOG-NEED
    return NULL;
  }

  table->used_count++;
  table->free_count--;
  return cbi;
}
