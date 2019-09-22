#ifndef FUNCTION_WRAPPER_X64_H_
#define FUNCTION_WRAPPER_X64_H_

#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

#if TARGET_ARCH_IA32
#elif TARGET_ARCH_X64
#include "InterceptRouting/x64/X64InterceptRouting.h"
#elif TARGET_ARCH_ARM64
#include "InterceptRouting/arm64/ARM64InterceptRouting.h"
#elif TARGET_ARCH_ARM
#else
#error "unsupported architecture"
#endif

class FunctionWrapperRouting : public InterceptRouting {
public:
  FunctionWrapperRouting(HookEntry *entry) : InterceptRouting(entry) {
  }

  void Dispatch();

  void *GetTrampolineTarget();

private:
  void BuildPreCallRouting();

  void BuildPostCallRouting();

private:
  void *prologue_dispatch_bridge;

  void *epilogue_dispatch_bridge;
};

#endif
