#pragma once

#include "dobby/common.h"
#include "InterceptRouting/InterceptRouting.h"
#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

struct InlineHookRouting : InterceptRouting {
  addr_t fake_func;

  InlineHookRouting(Interceptor::Entry *entry, addr_t fake_func) : InterceptRouting(entry), fake_func(fake_func) {
  }

  ~InlineHookRouting() = default;

  addr_t TrampolineTarget() override {
    return fake_func;
  }

  void BuildRouting() {
    __FUNC_CALL_TRACE__();

    GenerateTrampoline();

    GenerateRelocatedCode();

    BackupOriginCode();
  }
};

PUBLIC inline int DobbyHook(void *address, void *fake_func, void **out_origin_func) {
  __FUNC_CALL_TRACE__();
  if (!address) {
    ERROR_LOG("address is 0x0");
    return -1;
  }

  features::apple::arm64e_pac_strip(address);
  features::apple::arm64e_pac_strip(fake_func);
  features::android::make_memory_readable(address, 4);

  DEBUG_LOG("----- [DobbyHook: %p] -----", address);

  auto entry = gInterceptor.find((addr_t)address);
  if (entry) {
    ERROR_LOG("%p already been hooked.", address);
    return -1;
  }

  entry = new Interceptor::Entry((addr_t)address);
  entry->fake_func_addr = (addr_t)fake_func;

  auto routing = new InlineHookRouting(entry, (addr_t)fake_func);
  routing->BuildRouting();
  routing->Active();
  entry->routing = routing;

  if (routing->error) {
    ERROR_LOG("build routing error.");
    return -1;
  }

  if (out_origin_func) {
    *out_origin_func = (void *)entry->relocated.addr();
  }
  features::apple::arm64e_pac_strip_and_sign(*out_origin_func);

  gInterceptor.add(entry);

  return 0;
}
