#ifndef interceptor_routing_h
#define interceptor_routing_h

#include "closure_bridge.h"
#include "core.h"
#include "hookzz.h"
#include "interceptor.h"

ARCH_API void *get_ret_addr_PTR(RegState *rs);

ARCH_API void *get_next_hop_addr_PTR(RegState *rs);

ARCH_API void *get_current_fp_reg();

void interceptor_routing_begin(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR, void *ret_addr_PTR);

void interceptor_routing_end(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR);

void interceptor_routing_dynamic_binary_instrumentation(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR);

void interceptor_routing_begin_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info);

void interceptor_routing_end_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info);

void interceptor_routing_dynamic_binary_instrumentation_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info);

void interceptor_routing_common_bridge_handler(RegState *rs, ClosureBridgeInfo *cb_info);

#if DYNAMIC_CLOSURE_BRIDGE
void interceptor_routing_begin_dynamic_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcb_info);

void interceptor_routing_end_dynamic_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcb_info);

void interceptor_routing_dynamic_common_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcb_info);
#endif

#endif