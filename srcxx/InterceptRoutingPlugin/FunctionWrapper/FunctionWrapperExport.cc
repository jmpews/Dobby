#include "hookzz_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting.h"

#include "InterceptRoutingPlugin/FunctionWrapper/function-wrapper-x64.h"

PUBLIC RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call) {
  HOOKZZ_DLOG("[*] Initialize 'ZzWrap' hook at %p\n", function_address);

  Interceptor *interceptor = Interceptor::SharedInstance();

  HookEntry *entry        = new HookEntry();
  entry->id               = interceptor->entries->getCount();
  entry->pre_call         = pre_call;
  entry->post_call        = post_call;
  entry->type             = kFunctionWrapper;
  entry->function_address = function_address;

  FunctionWrapperRouting *route = new FunctionWrapperRouting(entry);
  route->Dispatch();
  interceptor->AddHookEntry(entry);
  route->Commit();

  HOOKZZ_DLOG("[*] Finalize %p\n", function_address);
  return RS_SUCCESS;
}
