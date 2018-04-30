//
// Created by z on 2018/4/7.
//

#include "custom-bridge-handler.h"
#include "closure-bridge-x86.h"
#include <CommonKit/log/log_kit.h>
#include <debuglog.h>
#include <hookzz.h>

void context_begin_invocation(RegState *rs, HookEntry *entry, void *nextHop, void *retAddr) {

}

void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    return;
}

void context_end_invocation(RegState *rs, HookEntry *entry, void *nextHop) {
}

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    return;
}

void dynamic_binary_instrumentation_invocation(RegState *rs, HookEntry *entry, void *nextHop) {
}

void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    return;
}