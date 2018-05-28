//
// Created by z on 2018/4/7.
//

#ifndef CUSTOM_BRIDGE_HANDLER_H
#define CUSTOM_BRIDGE_HANDLER_H

#include "closure-bridge-arm64.h"
#include "hookzz.h"
#include "interceptor.h"
#include "zkit.h"

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd);
void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd);
void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeData *cbd);
void context_begin_only_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd);

#endif //CUSTOM_BRIDGE_HANDLER_H
