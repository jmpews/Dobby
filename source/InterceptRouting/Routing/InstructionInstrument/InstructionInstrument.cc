#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/Routing/InstructionInstrument/InstructionInstrumentRouting.h"

PUBLIC int DobbyInstrument(void *address, dobby_instrument_callback_t pre_handler) {
  if (!address) {
    ERROR_LOG("address is 0x0.\n");
    return RS_FAILED;
  }

#if defined(__arm64__) && __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
#endif

#if defined(ANDROID)
  OSMemory::SetPermission((void *)address, OSMemory::PageSize(), kReadExecute);
#endif

  DLOG(0, "\n\n----- [DobbyInstrument:%p] -----", address);

  // check if already instrument
#if defined(__arm64__) && __has_feature(ptrauth_calls)
  address = ptrauth_strip(address, ptrauth_key_asia);
#endif
  auto entry = Interceptor::SharedInstance()->findHookEntry((addr_t)address);
  if (entry) {
    ERROR_LOG("%s already been instrumented.", address);
    return RS_FAILED;
  }

  entry = new HookEntry;
  entry->id = Interceptor::SharedInstance()->count();
  entry->type = kInstructionInstrument;
  entry->patched_addr = (addr_t)address;

  auto routing = new InstructionInstrumentRouting(entry, pre_handler, nullptr);
  routing->Prepare();
  routing->DispatchRouting();
  routing->Commit();

  Interceptor::SharedInstance()->addHookEntry(entry);

  return RS_SUCCESS;
}
