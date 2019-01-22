#ifndef FUNCTION_WRAPPER_ARM64_H_
#define FUNCTION_WRAPPER_ARM64_H_

#include "hookzz_internal.h"

#include "AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

#include "InterceptRouting/arm64/ARM64InterceptRouting.h"

class DynamicBinaryInstrumentRouting : public ARM64InterceptRouting {
public:

  DynamicBinaryInstrumentRouting(HookEntry *entry) : ARM64InterceptRouting(entry) {}

private:
  virtual void Active();

  virtual void BuildDynamicBinaryInstrumentationRouting();
private:
  void *prologue_dispatch_bridge;
};

#endif
