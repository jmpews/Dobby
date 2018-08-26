#ifndef ZZ_SRCXX_INTERCEPT_ROUTING_HANDLER_H_
#define ZZ_SRCXX_INTERCEPT_ROUTING_HANDLER_H_

#include "hookzz.h"
#include "srcxx/hookzz_internal.h"
#include "srcxx/Interceptor.h"
#include "srcxx/ClosureBridge.h"

// get the origin function ret address, such as ARM64, will return the LR register
void *get_func_ret_address(RegisterContext *reg_ctx);

// set the origin function ret address, such as ARM64, will repace the LR register
void set_func_ret_address(RegisterContext *reg_ctx, void *address);

// set the next hop at the begin of function running
void set_prologue_routing_next_hop(RegisterContext *reg_ctx, void *address)

void prologue_routing_dispatch(RegisterContext *reg_ctx, ClosureBridgeInfo *cbInfo);

void epilogue_routing_dispatch(RegisterContext *reg_ctx, ClosureBridgeInfo *cbInfo);

void pre_call_forward_handler(RegisterContext *reg_ctx, HookEntry *entry);

void post_call_forward_handler(RegisterContext *reg_ctx, HookEntry *entry);

void replace_call_handler(RegisterContext *reg_ctx, HookEntry *entry)

void intercept_routing_post_call(RegisterContext *reg_ctx, HookEntry *entry, void *next_hop_addr_PTR);

void intercept_routing_dynamic_binary_instrumentation(RegisterContext *rs, hook_entry_t *entry, void *next_hop_addr_PTR);


void interceptor_routing_end_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cbInfo);

void interceptor_routing_dynamic_binary_instrumentation_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cbInfo);

void interceptor_routing_common_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cbInfo);

void interceptor_routing_begin_dynamic_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcbInfo);

void interceptor_routing_end_dynamic_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcbInfo);

void interceptor_routing_dynamic_common_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcbInfo);
#endif