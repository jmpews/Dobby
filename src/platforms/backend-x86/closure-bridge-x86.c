#include "closure-bridge-x86.h"
#include "backend-x86-helper.h"
#include <string.h>

#include <CommonKit/log/log_kit.h>

#include <sys/mman.h>
#include <unistd.h>

#define closure_bridge_trampoline_template_length (7 * 4)

static ClosureTrampolineTable *gClosureBridageTrampolineTable = NULL;

void common_bridge_handler(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry) {
}

static ClosureTrampolineTable *ClosureTrampolineTableAllocate(void) {
  return NULL;
}

static void ClosureTrampolineTableFree(ClosureTrampolineTable *table) {
  return;
}

ClosureTrampolineEntry *ClosureBridgeAllocate(void *carry_data, void *forward_code) {
  return NULL;
}

static void ClosureBridgeFree(ClosureTrampolineEntry *bridgeData) {
  return;
}