//
// Created by jmpews on 2018/6/14.
//

#include "hookzz.h"

#include "Interceptor.h"
#include "InterceptorBackend.h"
#include "Trampoline.h"

RetStatus ZzHook(void *target_address, void *replace_call, void **origin_call, PRECALL pre_call, POSTCALL post_call) {
  HookType type;
  if (pre_call || post_call) {
    type = HOOK_TYPE_FUNCTION_via_PRE_POST;
  } else {
    type = HOOK_TYPE_FUNCTION_via_REPLACE;
  }

  HookEntry *entry      = new (HookEntry);
  entry->target_address = target_address;
  entry->replace_call   = replace_call;
  entry->pre_call       = pre_call;
  entry->post_call      = post_call;

  Interceptor *interceptor = Interceptor::GETInstance();
  interceptor->addHookEntry(entry);
  interceptor->backend->BuildAllTrampoline(entry);
  interceptor->backend->ActiveTrampoline(entry);
  return RS_SUCCESS;
}