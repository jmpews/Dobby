//
// Created by z on 2018/4/7.
//

#ifndef CUSTOM_BRIDGE_HANDLER_H
#define CUSTOM_BRIDGE_HANDLER_H

#include "hookzz.h"
#include "interceptor.h"
#include "zkit.h"

#include "closurebridge.h"

void dynamic_common_bridge_handler(RegState *rs, ClosureBridgeData *cbd);

void common_bridge_handler(RegState *rs, ClosureBridgeData *cbd);

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd);

void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd);

void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeData *cbd);

#endif //CUSTOM_BRIDGE_HANDLER_H
