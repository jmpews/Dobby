#include "dobby/common.h"
#include "Interceptor.h"
#include "InterceptRouting/InlineHookRouting.h"
#include "InterceptRouting/InstrumentRouting.h"
#include "InterceptRouting/NearBranchTrampoline/NearBranchTrampoline.h"
#include  "TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.h"

__attribute__((constructor)) static void ctor() {
  DEBUG_LOG("================================");
  DEBUG_LOG("Dobby");
  DEBUG_LOG("dobby in debug log mode, disable with cmake flag \"-DDOBBY_DEBUG=OFF\"");
  DEBUG_LOG("================================");
}

PUBLIC int DobbyDestroy(void *address) {
  features::arm_thumb_fix_addr((uintptr_t &)address);
  auto entry = gInterceptor.find((addr_t)address);
  if (entry) {
    DobbyCodePatch(address, entry->origin_code_buffer, entry->patched.size);
    gInterceptor.remove((addr_t)address);
    return 0;
  }

  return -1;
}

PUBLIC int placeholder() {
  &DobbyHook;
  &DobbyInstrument;
  &dobby_enable_near_trampoline;
  &dobby_disable_near_trampoline;
  &common_closure_bridge_handler;
  return 0;
}
