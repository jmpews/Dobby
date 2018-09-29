#include "hookzz_internal.h"
#include "Interceptor.h"

#include "InterceptRouting.h"

PUBLIC RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call) {
  DLOG("[*] Initialize 'ZzWrap' hook at %p\n", function_address);

  Interceptor *intercepter = Interceptor::SharedInstance();

  HookEntry *entry        = new HookEntry();
  entry->id               = intercepter->entries.size();
  entry->pre_call         = pre_call;
  entry->post_call        = post_call;
  entry->type             = kFunctionWrapper;
  entry->function_address = function_address;

  InterceptRouting *route = InterceptRouting::New(entry);
  route->Dispatch();
  intercepter->AddHookEntry(entry);
  route->Commit();

  DLOG("[*] Finalize %p\n", function_address);
  return RS_SUCCESS;
}

PUBLIC RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call) {
  DLOG("[*] Initialize 'ZzReplace' hook at %p\n", function_address);
  
  Interceptor *intercepter = Interceptor::SharedInstance();
  
  HookEntry *entry        = new HookEntry();
  entry->id               = intercepter->entries.size();
  entry->type             = kFunctionInlineHook;
  entry->function_address = function_address;
  
  InterceptRouting *route = InterceptRouting::New(entry);
  route->Dispatch();
  intercepter->AddHookEntry(entry);
  route->Commit();
  
  DLOG("[*] Finalize %p\n", function_address);
  return RS_SUCCESS;
}

PUBLIC RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL) {
  DLOG("[*] Initialize 'ZzDynamicBinaryInstrumentation' hook at %p\n", inst_address);
  
  Interceptor *intercepter = Interceptor::SharedInstance();
  
  HookEntry *entry        = new HookEntry();
  entry->id               = intercepter->entries.size();
  entry->type = kDynamicBinaryInstrumentation;
  entry->instruction_address = inst_address;
  
  InterceptRouting *route = InterceptRouting::New(entry);
  route->Dispatch();
  intercepter->AddHookEntry(entry);
  route->Commit();
  
  DLOG("[*] Finalize %p\n", inst_address);
  return RS_SUCCESS;
}
