#ifndef HOOKZZ_ARCH_X64_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_X64_INTERCEPT_ROUTING_H_

#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InterceptRouting/InterceptRouting.h"
#include "Interceptor.h"

class X64InterceptRouting : public InterceptRouting {
public:
  RoutingType branch_type_;

public:
  X64InterceptRouting(HookEntry *entry) : InterceptRouting(entry) {
  }

  virtual void Dispatch() = 0;

  void Active();

  virtual void *GetTrampolineTarget() = 0;

  void Prepare();

private:
};

#endif
