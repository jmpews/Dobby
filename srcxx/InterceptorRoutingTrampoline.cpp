//
// Created by jmpews on 2018/6/15.
//

#include "InterceptorBackend.h"

void InterceptorRoutingTrampoline::BuildAllTrampoline(HookEntry *entry) {
  if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
    Prepare(entry);
    BuildForEnter(entry);
    BuildForInvoke(entry);
    BuildForLeave(entry);
  } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
    Prepare(entry);
    BuildForEnterTransfer(entry);
    BuildForInvoke(entry);
  } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
    BuildForEnter(entry);
    BuildForLeave(entry);
  } else if (entry->hook_type == HOOK_TYPE_INSTRUCTION_via_DBI) {
    Prepare(entry);
    BuildForDynamicBinaryInstrumentation(entry);
    BuildForInvoke(entry);
  }
}