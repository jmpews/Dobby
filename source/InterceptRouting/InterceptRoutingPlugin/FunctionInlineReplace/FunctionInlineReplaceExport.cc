#include "dobby_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"

#include "function-inline-replace.h"

PUBLIC int DobbyHook(void *function_address, void *replace_call, void **origin_call) {
  if (!function_address)
    FATAL("function address is 0x0");

  DLOG("Initialize DobbyHook => %p => %p", function_address, replace_call);

  Interceptor *interceptor = Interceptor::SharedInstance();
  if (interceptor->FindHookEntry(function_address)) {
    FATAL_LOG("function %s already been hooked.", function_address);
    return RS_FAILED;
  }

  HookEntry *entry        = new HookEntry();
  entry->id               = interceptor->entries->getCount();
  entry->type             = kFunctionInlineHook;
  entry->function_address = function_address;

  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry, replace_call);
  route->Dispatch();
  interceptor->AddHookEntry(entry);

  // SET BEFORE `route->Commit()` !!!
  // set origin call with relocated function
  *origin_call = entry->relocated_origin_function;

  // code patch & hijack original control flow entry
  route->Commit();

  return RS_SUCCESS;
}
