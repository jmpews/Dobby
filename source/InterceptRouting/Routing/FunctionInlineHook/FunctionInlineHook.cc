#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHookRouting.h"

PUBLIC int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func) {
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

  // check if already register
  auto entry = Interceptor::SharedInstance()->findHookEntry((addr_t)address);
  if (entry) {
    ERROR_LOG("%p already been hooked.", address);
    return RS_FAILED;
  }

  entry = new HookEntry();
  entry->id = Interceptor::SharedInstance()->count();
  entry->type = kFunctionInlineHook;
  entry->patched_addr = (addr_t)address;

  auto *routing = new FunctionInlineHookRouting(entry, replace_func);
  routing->Prepare();
  routing->DispatchRouting();

  // set origin func entry with as relocated instructions
  if (origin_func) {
    *origin_func = (dobby_dummy_func_t)entry->relocated_addr;
  }

  routing->Commit();

  Interceptor::SharedInstance()->addHookEntry(entry);

  return RS_SUCCESS;
}
