#include "dobby.h"
#include "dobby/common.h"
#include "Interceptor.h"
#include "InterceptRouting/InlineHookRouting.h"
#include "InterceptRouting/InstrumentRouting.h"
#include "InterceptRouting/NearBranchTrampoline/NearBranchTrampoline.h"
#include "TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.h"
#include "MemoryAllocator/NearMemoryAllocator.h"
#include <stdint.h>

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
    gInterceptor.remove((addr_t)address);
    entry->restore_orig_code();
    delete entry;
    return 0;
  }

  return -1;
}

PUBLIC void dobby_set_options(bool enable_near_trampoline, dobby_alloc_near_code_callback_t alloc_near_code_callback) {
  dobby_set_near_trampoline(enable_near_trampoline);
  dobby_register_alloc_near_code_callback(alloc_near_code_callback);
}

PUBLIC uintptr_t placeholder() {
  uintptr_t x = 0;
  x += (uintptr_t)&DobbyHook;
  x += (uintptr_t)&DobbyInstrument;
  x += (uintptr_t)&dobby_set_near_trampoline;
  x += (uintptr_t)&common_closure_bridge_handler;
  x += (uintptr_t)&dobby_register_alloc_near_code_callback;
  return x;
}
