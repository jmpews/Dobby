#ifndef HOOKZZ_INTERCEPT_ROUTING_HANDLER_H_
#define HOOKZZ_INTERCEPT_ROUTING_HANDLER_H_

#include "AssemblyClosureTrampoline.h"
#include "Interceptor.h"
#include "hookzz_internal.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void get_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address);

void set_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address);

void intercept_routing_common_bridge_handler(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif