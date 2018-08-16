//
// Created by z on 2018/4/7.
//

#include "custom-bridge-handler-arm64.h"
#include "Invocation.h"
#include "hookzz.h"

void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {
  HookEntry *entry = (HookEntry *)cbInfo->user_data;
  void *nextHopPTR = (void *)&rs->general.regs.x15;
  void *regLRPTR   = (void *)&rs->lr;
  context_begin_invocation(rs, entry, nextHopPTR, regLRPTR);
  return;
}

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {
  HookEntry *entry = (HookEntry *)cbInfo->user_data;
  void *nextHopPTR = (void *)&rs->general.regs.x15;
  context_end_invocation(rs, entry, nextHopPTR);
  return;
}

void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {
  HookEntry *entry = (HookEntry *)cbInfo->user_data;
  void *nextHopPTR = (void *)&rs->general.regs.x15;
  dynamic_binary_instrumentation_invocation(rs, entry, nextHopPTR);
  return;
}

void dynamic_context_begin_invocation_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo) {
  HookEntry *entry = (HookEntry *)dcbInfo->user_data;
  void *nextHopPTR = (void *)&rs->general.regs.x15;
  void *regLRPTR   = (void *)&rs->lr;
  context_begin_invocation(rs, entry, nextHopPTR, regLRPTR);
  return;
}

void dynamic_context_end_invocation_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo) {
  HookEntry *entry = (HookEntry *)dcbInfo->user_data;
  void *nextHopPTR = (void *)&rs->general.regs.x15;
  context_end_invocation(rs, entry, nextHopPTR);
  return;
}

void dynamic_common_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo) {

  DYNAMIC_USER_CODE_CALL userCodeCall = (DYNAMIC_USER_CODE_CALL)dcbInfo->user_code;
  // printf("CommonBridgeHandler:");
  // printf("\tTrampoline Address: %p", cbInfo->redirect_trampoline);
  userCodeCall(rs, dcbInfo);
  // set return address
  rs->general.x[15] = rs->general.x[15];
  return;
}

void common_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {

  USER_CODE_CALL userCodeCall = (USER_CODE_CALL)cbInfo->user_code;
  // printf("CommonBridgeHandler:");
  // printf("\tTrampoline Address: %p", cbInfo->redirect_trampoline);
  userCodeCall(rs, cbInfo);
  // set return address
  rs->general.x[15] = rs->general.x[15];
  return;
}