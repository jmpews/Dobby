//
// Created by z on 2018/4/7.
//

#include "custom-bridge-handler.h"
#include "closure-bridge-arm.h"
#include <CommonKit/log/log_kit.h>
#include <debuglog.h>
#include <hookzz.h>

void context_begin_invocation(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR, void *ret_addr_PTR) {
  // DEBUG_LOG("target %p call begin-invocation", entry->target_ptr);

  // For iOS Easy Debug Breakpoint
  // if (!strcmp((char *)(rs->general.regs.x1), "_beginBackgroundTaskWithName:expirationHandler:")) {
  // }

  ThreadStack *threadstack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
  if (!threadstack) {
    threadstack = ThreadStackAllocate(entry->thread_local_key);
  }
  CallStack *callstack = CallStackAllocate();
  ThreadStackPushCallStack(threadstack, callstack);

  // call pre_call
  if (entry->pre_call) {
    PRECALL pre_call;
    HookEntryInfo entryInfo;
    entryInfo.hook_id        = entry->id;
    entryInfo.target_address = entry->target_ptr;
    pre_call                 = entry->pre_call;
    (*pre_call)(rs, (ThreadStackPublic *)threadstack, (CallStackPublic *)callstack, &entryInfo);
  }

  // set next hop
  if (entry->replace_call) {
    *(zz_ptr_t *)next_hop_addr_PTR = entry->replace_call;
  } else {
    *(zz_ptr_t *)next_hop_addr_PTR = entry->on_invoke_trampoline;
  }

  if (entry->type == HOOK_TYPE_FUNCTION_via_PRE_POST || entry->type == HOOK_TYPE_FUNCTION_via_GOT) {
    callstack->ret_addr_PTR   = *(zz_ptr_t *)ret_addr_PTR;
    *(zz_ptr_t *)ret_addr_PTR = entry->on_leave_trampoline;
  }
}

void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info) {
  hook_entry_t *entry = cb_info->user_data;
  void *nextHopPTR    = (void *)&rs->general.regs.r12;
  void *regLRPTR      = (void *)&rs->lr;
  context_begin_invocation(rs, entry, nextHopPTR, regLRPTR);
  return;
}

void context_end_invocation(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR) {
  // DEBUG_LOG("%p call end-invocation", entry->target_ptr);

  ThreadStack *threadstack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
  if (!threadstack) {
  }
  CallStack *callstack = ThreadStackPopCallStack(threadstack);

  // call post_call
  if (entry->post_call) {
    POSTCALL post_call;
    HookEntryInfo entryInfo;
    entryInfo.hook_id        = entry->id;
    entryInfo.target_address = entry->target_ptr;
    post_call                = entry->post_call;
    (*post_call)(rs, (ThreadStackPublic *)threadstack, (CallStackPublic *)callstack, (const HookEntryInfo *)&entryInfo);
  }

  // set next hop
  *(zz_ptr_t *)next_hop_addr_PTR = callstack->ret_addr_PTR;
  CallStackFree(callstack);
}

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info) {
  hook_entry_t *entry = cb_info->user_data;
  void *nextHopPTR    = (void *)&rs->general.regs.r12;
  context_end_invocation(rs, entry, nextHopPTR);
  return;
}

void dynamic_binary_instrumentation_invocation(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR) {
  DEBUG_LOG("target %p call dynamic-binary-instrumentation-invocation", entry->target_ptr);

  /* call pre_call */
  if (entry->dbi_call) {
    DBICALL dbi_call;
    HookEntryInfo entryInfo;
    entryInfo.hook_id        = entry->id;
    entryInfo.target_address = entry->target_ptr;
    dbi_call                 = entry->dbi_call;
    (*dbi_call)(rs, (const HookEntryInfo *)&entryInfo);
  }

  *(zz_ptr_t *)next_hop_addr_PTR = entry->on_invoke_trampoline;
}

void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info) {
  hook_entry_t *entry = cb_info->user_data;
  void *nextHopPTR    = (void *)&rs->general.regs.r12;
  dynamic_binary_instrumentation_invocation(rs, entry, nextHopPTR);
  return;
}