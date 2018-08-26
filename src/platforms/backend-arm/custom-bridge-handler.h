//
// Created by z on 2018/4/7.
//

#ifndef CUSTOM_BRIDGE_HANDLER_H
#define CUSTOM_BRIDGE_HANDLER_H

#include "closure-bridge-arm.h"
#include "hookzz.h"
#include "interceptor.h"
#include "zkit.h"

void dynamic_context_begin_invocation_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcb_info);

void dynamic_context_end_invocation_bridge_handler(RegisterContext *rs, DynamicClosureBridgeInfo *dcb_info);

void context_begin_invocation_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cb_info);

void context_end_invocation_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cb_info);

void dynamic_binary_instrumentationn_bridge_handler(RegisterContext *rs, ClosureBridgeInfo *cb_info);

#endif //CUSTOM_BRIDGE_HANDLER_H
