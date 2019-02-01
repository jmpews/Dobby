#include "hookzz_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace-x64.h"

PUBLIC RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call) {
  DLOG("[*] Initialize 'ZzReplace' hook at %p\n", function_address);

  Interceptor *interceptor = Interceptor::SharedInstance();

  HookEntry *entry        = new HookEntry();
  entry->id               = interceptor->entries->getCount();
  entry->replace_call     = replace_call;
  entry->type             = kFunctionInlineHook;
  entry->function_address = function_address;

  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry);
  route->Dispatch();
  interceptor->AddHookEntry(entry);

  // SET BEFORE `route->Commit()` !!!
  // set origin call with relocated function
  *origin_call = entry->relocated_origin_function;

  route->Commit();

  DLOG("[*] Finalize %p\n", function_address);
  return RS_SUCCESS;
}