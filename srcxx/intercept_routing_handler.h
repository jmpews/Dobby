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
void set_prologue_routing_next_hop(RegisterContext *reg_ctx, void *address);

// set the next hop of the epilogue that before function return;
void set_epilogue_routing_next_hop(RegisterContext *reg_ctx, void *address);

void prologue_routing_dispatch(RegisterContext *reg_ctx, ClosureBridgeInfo *cb_info);

void epilogue_routing_dispatch(RegisterContext *reg_ctx, ClosureBridgeInfo *cb_info);

void pre_call_forward_handler(RegisterContext *reg_ctx, HookEntry *entry);

void post_call_forward_handler(RegisterContext *reg_ctx, HookEntry *entry);

void interceptor_routing_common_bridge_handler(RegisterContext *reg_ctx, ClosureBridgeInfo *cb_info);

#if 0
void interceptor_routing_begin_dynamic_bridge_handler(RegisterContext *reg_ctx, DynamicClosureBridgeInfo *dcbInfo);

void interceptor_routing_end_dynamic_bridge_handler(RegisterContext *reg_ctx, DynamicClosureBridgeInfo *dcbInfo);

void interceptor_routing_dynamic_common_bridge_handler(RegisterContext *reg_ctx, DynamicClosureBridgeInfo *dcbInfo);
#endif

#endif