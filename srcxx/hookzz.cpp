#include "Interceptor.h"
#include "hookzz_internal.h"

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
  entry->replace_call     = replace_call;
  entry->type             = kFunctionInlineHook;
  entry->function_address = function_address;

  InterceptRouting *route = InterceptRouting::New(entry);
  route->Dispatch();
  intercepter->AddHookEntry(entry);
  route->Commit();

  // set origin call with relocated function
  *origin_call = entry->relocated_origin_function;

  DLOG("[*] Finalize %p\n", function_address);
  return RS_SUCCESS;
}

PUBLIC RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL dbi_call) {
  DLOG("[*] Initialize 'ZzDynamicBinaryInstrumentation' hook at %p\n", inst_address);

  Interceptor *intercepter = Interceptor::SharedInstance();

  HookEntry *entry           = new HookEntry();
  entry->id                  = intercepter->entries.size();
  entry->dbi_call            = dbi_call;
  entry->type                = kDynamicBinaryInstrumentation;
  entry->instruction_address = inst_address;

  InterceptRouting *route = InterceptRouting::New(entry);
  route->Dispatch();
  intercepter->AddHookEntry(entry);
  route->Commit();

  DLOG("[*] Finalize %p\n", inst_address);
  return RS_SUCCESS;
}

PUBLIC RetStatus zz_enable_arm_arm64_b_branch() {
  DLOG("%s", "[*] Enable Intercepter ARM/ARM64 B Branch\n");

  Interceptor *intercepter = Interceptor::SharedInstance();
  // TODO: replace with getter or setter
  intercepter->enable_arm_arm64_b_branch();

  return RS_SUCCESS;
}

PUBLIC RetStatus zz_disable_arm_arm64_b_branch() {
  DLOG("%s", "[*] Enable Intercepter ARM/ARM64 B Branch\n");

  Interceptor *intercepter = Interceptor::SharedInstance();
  // TODO: replace with getter or setter
  intercepter->disable_arm_arm64_b_branch();

  return RS_SUCCESS;
}
