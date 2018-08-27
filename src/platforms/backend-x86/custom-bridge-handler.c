//
// Created by z on 2018/4/7.
//

#include "custom-bridge-handler.h"
#include "closure-bridge-x86.h"
#include <CommonKit/log/log_kit.h>
#include <debuglog.h>
#include <hookzz.h>

void context_begin_invocation(RegisterContext *reg_ctx, hook_entry_t *entry, void *next_hop_addr_PTR,
                              void *ret_addr_PTR) {
}

void context_begin_invocation_bridge_handler(RegisterContext *reg_ctx, ClosureBridgeInfo *cb_info) {
  return;
}

void context_end_invocation(RegisterContext *reg_ctx, hook_entry_t *entry, void *next_hop_addr_PTR) {
}

void context_end_invocation_bridge_handler(RegisterContext *reg_ctx, ClosureBridgeInfo *cb_info) {
  return;
}

void dynamic_binary_instrumentation_invocation(RegisterContext *reg_ctx, hook_entry_t *entry, void *next_hop_addr_PTR) {
}

void dynamic_binary_instrumentationn_bridge_handler(RegisterContext *reg_ctx, ClosureBridgeInfo *cb_info) {
  return;
}