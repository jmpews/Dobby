#include "srcxx/intercept_routing_handler.h"

void pre_call_forward_handler(RegisterContext *reg_ctx, HookEntry *entry) {

  // run the `pre_call` before execute origin function which has been relocated(fixed)
  if (entry->pre_call) {
    PRECALL pre_call;
    HookEntryInfo entry_info;
    entry_info.hook_id        = entry->id;
    entry_info.target_address = entry->target_address;
    pre_call                 = entry->pre_call;
    (*pre_call)(reg_ctx, &entry_info);
  }

  // run the origin function that the patched instructions has been relocated
  set_prologue_routing_next_hop(reg_ctx, entry->relocated_origin_function);

  // replace the function ret address with our epilogue_routing_dispatch
  set_func_ret_address(reg_ctx, entry->epilogue_dispatch_bridge);
}

void post_call_forward_handler(RegisterContext *rs, hook_entry_t *entry, void *next_hop_addr_PTR) {
  // DEBUG_LOG("%p call end-invocation", entry->target_ptr);

  // call post_call
  if (entry->post_call) {
    POSTCALL post_call;
    HookEntryInfo entryInfo;
    entryInfo.hook_id        = entry->id;
    entryInfo.target_address = entry->target_address;
    post_call                = entry->post_call;
    (*post_call)(rs, (ThreadStackPublic *)NULL, (CallStackPublic *)NULL, (const HookEntryInfo *)&entryInfo);
  }

  // TODO
  // set next hop
  // *(zz_ptr_t *)next_hop_addr_PTR = callStack->ret_addr_PTR;
}

void interceptor_routing_dynamic_binary_instrumentation(RegisterContext *rs, hook_entry_t *entry, void *next_hop_addr_PTR) {
  // DEBUG_LOG("target %p call dynamic-binary-instrumentation-invocation", entry->target_ptr);

  if (entry->stub_call) {
    STUBCALL stub_call;
    HookEntryInfo entryInfo;
    entryInfo.hook_id        = entry->id;
    entryInfo.target_address = entry->target_address;
    stub_call                = entry->stub_call;
    (*stub_call)(rs, (const HookEntryInfo *)&entryInfo);
  }

  *(zz_ptr_t *)next_hop_addr_PTR = entry->on_invoke_trampoline;
}

void (RegisterContext *rs, ClosureBridgeInfo *cbInfo) {
  hook_entry_t *entry     = cbInfo->user_data;
  void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
  void *ret_addr_PTR      = get_ret_addr_PTR(rs);
  interceptor_routing_begin(rs, entry, next_hop_addr_PTR, ret_addr_PTR);
  return;
}

void interceptor_routing_end_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cbInfo) {
  hook_entry_t *entry     = cbInfo->user_data;
  void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
  interceptor_routing_end(rs, entry, next_hop_addr_PTR);
  return;
}

void interceptor_routing_dynamic_binary_instrumentation_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cbInfo) {
  hook_entry_t *entry     = cbInfo->user_data;
  void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
  interceptor_routing_dynamic_binary_instrumentation(rs, entry, next_hop_addr_PTR);
  return;
}

void interceptor_routing_common_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cbInfo) {
  USER_CODE_CALL userCodeCall = cbInfo->user_code;
  userCodeCall(rs, cbInfo);
  return;
}

void interceptor_routing_begin_dynamic_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcbInfo) {
  hook_entry_t *entry     = dcbInfo->user_data;
  void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
  void *ret_addr_PTR      = get_ret_addr_PTR(rs);
  interceptor_routing_begin(rs, entry, next_hop_addr_PTR, ret_addr_PTR);
  return;
}

void interceptor_routing_end_dynamic_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcbInfo) {
  hook_entry_t *entry     = dcbInfo->user_data;
  void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
  interceptor_routing_end(rs, entry, next_hop_addr_PTR);
  return;
}

void interceptor_routing_dynamic_common_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcbInfo) {
  DYNAMIC_USER_CODE_CALL userCodeCall = dcbInfo->user_code;
  userCodeCall(rs, dcbInfo);
  return;
}