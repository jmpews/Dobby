#include "closure-bridge-x86.h"
#include "backend-x86-helper.h"
#include <string.h>

#include <CommonKit/log/log_kit.h>

#include <sys/mman.h>
#include <unistd.h>

#define closure_bridge_trampoline_template_length (7 * 4)

static ClosureBridgeTrampolineTable *gClosureBridageTrampolineTable = NULL;

void common_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info) {
}

static ClosureBridgeTrampolineTable *ClosureBridgeTrampolineTableAllocate(void) {
  return NULL;
}

static void ClosureBridgeTrampolineTableFree(ClosureBridgeTrampolineTable *table) {
  return;
}

ClosureBridgeInfo *ClosureBridgeAllocate(void *user_data, void *user_code) {
  return NULL;
}

static void ClosureBridgeFree(ClosureBridgeInfo *bridgeData) {
  return;
}