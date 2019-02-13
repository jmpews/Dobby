#ifndef FUNCTION_WRAPPER_H_
#define FUNCTION_WRAPPER_H_

#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "InterceptRouting/InterceptRouting.h"
#include "Interceptor.h"

#if TARGET_ARCH_IA32
#elif TARGET_ARCH_X64
#include "InterceptRouting/x64/X64InterceptRouting.h"
#elif TARGET_ARCH_ARM64
#include "InterceptRouting/arm64/ARM64InterceptRouting.h"
#elif TARGET_ARCH_ARM
#include "InterceptRouting/arm/ARMInterceptRouting.h"
#else
#error "unsupported architecture"
#endif

class FunctionInlineReplaceRouting : public InterceptRouting {
public:
  FunctionInlineReplaceRouting(HookEntry *entry) : InterceptRouting(entry) {
  }

  void *GetTrampolineTarget();

  void Dispatch();

private:
  virtual void BuildReplaceRouting();
};

#endif
