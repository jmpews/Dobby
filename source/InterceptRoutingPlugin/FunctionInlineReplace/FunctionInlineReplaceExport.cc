#include "dobby_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"

#include "InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace.h"

PUBLIC int DobbyHook(void *function_address, void *replace_call, void **origin_call) {

  if (!function_address)
    FATAL("ERROR: the function address is 0x0.");

  DLOG("[*] Initialize 'DobbyHook' hook at %p", function_address);

  Interceptor *interceptor = Interceptor::SharedInstance();
  
  if(interceptor->FindHookEntry(function_address)) {
    DLOG("ERROR: function %s already been hooked.", function_address);
    return (int)RS_FAILED;
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

  route->Commit();

  DLOG("[*] Finalize %p\n", function_address);
  return (int)RS_SUCCESS;
}
