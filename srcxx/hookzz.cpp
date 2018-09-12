#include "hookzz_internal.h"
#include "Interceptor.h"

#include "InterceptRouting.h"

PUBLIC RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call) {
  DLOG("[*] Initialize 'ZzWrap' hook at %p\n", function_address);

  Interceptor *intercepter = Interceptor::SharedInstance();

  HookEntry *entry        = new HookEntry;
  entry->id               = intercepter->entries.size();
  entry->pre_call         = pre_call;
  entry->post_call        = post_call;
  entry->type             = kFunctionWrapper;
  entry->function_address = function_address;

  InterceptRouting *route = new InterceptRouting(entry);
  route->Dispatch();
  intercepter->AddHookEntry(entry);

  DLOG("[*] Finalize 'ZzWrap' hook at %p\n", function_address);
}
