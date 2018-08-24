#ifndef CUSTOM_BRIDGE_HANDLER_H
#define CUSTOM_BRIDGE_HANDLER_H

#include "ClosureBridge.h"
#include "hookzz.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void dynamic_common_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo);

void common_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo);

void dynamic_context_begin_invocation_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo);

void dynamic_context_end_invocation_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo);

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo);

void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo);

void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //CUSTOM_BRIDGE_HANDLER_H
