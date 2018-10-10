#include "closure-bridge-arm.h"
#include "backend-arm-helper.h"
#include <string.h>

#include <CommonKit/log/log_kit.h>

#include <sys/mman.h>
#include <unistd.h>

#define closure_bridge_trampoline_template_length (4 * 4)

static ClosureTrampolineTable *gClosureBridageTrampolineTable;

void common_bridge_handler(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry) {

  USER_CODE_CALL userCodeCall = entry->forward_code;
  // printf("CommonBridgeHandler:");
  // printf("\tTrampoline Address: %p", entry->address);
  userCodeCall(reg_ctx, entry);
  // set return address
  reg_ctx->general.r[12] = reg_ctx->general.r[12];
  return;
}

static ClosureTrampolineTable *ClosureTrampolineTableAllocate(void) {
  void *mmap_page;
  long page_size;
  page_size = sysconf(_SC_PAGESIZE);

  mmap_page = mmap(0, 1, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (mmap_page == MAP_FAILED) {
    COMMON_ERROR_LOG();
    return NULL;
  }

  if (mprotect(mmap_page, (size_t)page_size, (PROT_WRITE | PROT_READ))) {
    COMMON_ERROR_LOG();
    return NULL;
  }

  int t              = page_size / closure_bridge_trampoline_template_length;
  void *copy_address = mmap_page;
  for (int i = 0; i < t; ++i) {
    copy_address = (void *)((intptr_t)mmap_page + i * closure_bridge_trampoline_template_length);
    memcpy(copy_address, closure_bridge_trampoline_template, closure_bridge_trampoline_template_length);
  }

  if (mprotect(mmap_page, (size_t)page_size, (PROT_READ | PROT_EXEC))) {
    COMMON_ERROR_LOG();
    return NULL;
  }

  ClosureTrampolineTable *table = (ClosureTrampolineTable *)malloc(sizeof(ClosureTrampolineTable));
  table->entry                        = mmap_page;
  table->trampoline_page              = mmap_page;
  table->used_count                   = 0;
  table->free_count                   = (uint16_t)t;
  return table;
}

static void ClosureTrampolineTableFree(ClosureTrampolineTable *table) {
  return;
}

ClosureTrampolineEntry *ClosureBridgeAllocate(void *carry_data, void *forward_code) {
  long page_size                      = sysconf(_SC_PAGESIZE);
  ClosureTrampolineTable *table = gClosureBridageTrampolineTable;
  if (table == NULL || table->free_count == 0) {
    table = ClosureTrampolineTableAllocate();
    if (table == NULL)
      return NULL;

    table->next = gClosureBridageTrampolineTable;
    if (table->next != NULL) {
      table->next->prev = table;
    }
    gClosureBridageTrampolineTable = table;
  }

  ClosureTrampolineEntry *bridgeData = (ClosureTrampolineEntry *)malloc(sizeof(ClosureTrampolineEntry));

  bridgeData->forward_code           = forward_code;
  bridgeData->carry_data           = carry_data;
  uint16_t trampoline_used_count  = gClosureBridageTrampolineTable->used_count;
  bridgeData->address = (void *)((intptr_t)gClosureBridageTrampolineTable->trampoline_page +
                                             closure_bridge_trampoline_template_length * trampoline_used_count);

  if (mprotect(gClosureBridageTrampolineTable->trampoline_page, (size_t)page_size, (PROT_READ | PROT_WRITE))) {
    COMMON_ERROR_LOG();
    return NULL;
  }

  // bind data to trampline
  void *tmp = (void *)((intptr_t)bridgeData->address + 4 * 2);
  memcpy(tmp, &bridgeData, sizeof(ClosureTrampolineEntry *));

  // set trampoline to bridge
  void *tmpX = (void *)closure_bridge_template;
  tmp        = (void *)((intptr_t)bridgeData->address + 4 * 3);
  memcpy(tmp, &tmpX, sizeof(void *));

  if (mprotect(gClosureBridageTrampolineTable->trampoline_page, (size_t)page_size, (PROT_READ | PROT_EXEC))) {
    COMMON_ERROR_LOG();
    return NULL;
  }

  table->used_count++;
  table->free_count--;

  return bridgeData;
}

static void ClosureBridgeFree(ClosureTrampolineEntry *bridgeData) {
  return;
}