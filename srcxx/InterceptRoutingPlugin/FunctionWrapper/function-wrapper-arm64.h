#ifndef FUNCTION_WRAPPER_ARM64_H_
#define FUNCTION_WRAPPER_ARM64_H_

#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

#include "InterceptRouting/arm64/ARM64InterceptRouting.h"

class FunctionWrapperRouting : public ARM64InterceptRouting {
public:
  FunctionWrapperRouting(HookEntry *entry) : ARM64InterceptRouting(entry) {
  }

  void *GetTrampolineTarget();

private:
  void BuildPreCallRouting();

  void BuildPostCallRouting();

private:
  void *prologue_dispatch_bridge;

  void *epilogue_dispatch_bridge;
};

#endif
