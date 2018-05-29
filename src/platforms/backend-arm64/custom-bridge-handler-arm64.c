//
// Created by z on 2018/4/7.
//

#include "custom-bridge-handler-arm64.h"
#include "invocation.h"

#include <CommonKit/log/log_kit.h>

#include <debuglog.h>
#include <hookzz.h>

void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    HookEntry *entry = cbd->user_data;
    void *nextHopPTR = (void *)&rs->general.regs.x15;
    void *regLRPTR   = (void *)&rs->lr;
    context_begin_invocation(rs, entry, nextHopPTR, regLRPTR);
    return;
}

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    HookEntry *entry = cbd->user_data;
    void *nextHopPTR = (void *)&rs->general.regs.x15;
    context_end_invocation(rs, entry, nextHopPTR);
    return;
}

void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    HookEntry *entry = cbd->user_data;
    void *nextHopPTR = (void *)&rs->general.regs.x15;
    dynamic_binary_instrumentation_invocation(rs, entry, nextHopPTR);
    return;
}

void dynamic_common_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {

    USER_CODE_CALL userCodeCall = cbd->user_code;
    // printf("CommonBridgeHandler:");
    // printf("\tTrampoline Address: %p", cbd->redirect_trampoline);
    userCodeCall(rs, cbd);
    // set return address
    rs->general.x[15] = rs->general.x[15];
    return;
}

void common_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {

    USER_CODE_CALL userCodeCall = cbd->user_code;
    // printf("CommonBridgeHandler:");
    // printf("\tTrampoline Address: %p", cbd->redirect_trampoline);
    userCodeCall(rs, cbd);
    // set return address
    rs->general.x[15] = rs->general.x[15];
    return;
}