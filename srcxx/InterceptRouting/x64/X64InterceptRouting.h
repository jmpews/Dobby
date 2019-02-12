#ifndef HOOKZZ_ARCH_X64_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_X64_INTERCEPT_ROUTING_H_

#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InterceptRouting/InterceptRouting.h"
#include "Interceptor.h"

class InterceptRouting : public InterceptRoutingBase {
public:
  RoutingType branch_type_;

public:
  InterceptRouting(HookEntry *entry) : InterceptRoutingBase(entry) {
  }

  virtual void Dispatch() = 0;

  void Active();

  virtual void *GetTrampolineTarget() = 0;

  void Prepare();

private:
};

#endif
