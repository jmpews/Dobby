#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/Routing/FunctionInlineReplace/function-inline-replace.h"

PUBLIC int DobbyHook(void *address, void *replace_call, void **origin_call) {
  if (!address) {
    ERROR_LOG("function address is 0x0");
    return RS_FAILED;
  }

#if defined(__arm64__) && __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
  replace_call = ptrauth_strip(replace_call, ptrauth_key_asia);
#endif

  RAW_LOG(1, "\n\n");
  DLOG(0, "----- [DobbyHook:%p] -----", address);

  // check if already hooked
  HookEntry *entry = Interceptor::SharedInstance()->FindHookEntry(address);
  if (entry) {
    FunctionInlineReplaceRouting *route = (FunctionInlineReplaceRouting *)entry->route;
    if (route->GetTrampolineTarget() == replace_call) {
      ERROR_LOG("function %p already been hooked.", address);
      return RS_FAILED;
    }
  }

  entry = new HookEntry();
  entry->id = Interceptor::SharedInstance()->GetHookEntryCount();
  entry->type = kFunctionInlineHook;
  entry->function_address = address;

  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry, replace_call);
  route->Prepare();
  route->DispatchRouting();
  Interceptor::SharedInstance()->AddHookEntry(entry);

  // set origin call with relocated function
  if (origin_call) {
    *origin_call = entry->relocated_origin_function;
  }

#if __has_feature(ptrauth_calls)
  *origin_call = ptrauth_strip(*origin_call, ptrauth_key_asia);
  *origin_call = ptrauth_sign_unauthenticated(*origin_call, ptrauth_key_asia, 0);
#endif

  // code patch & hijack original control flow entry
  route->Commit();

  return RS_SUCCESS;
}
