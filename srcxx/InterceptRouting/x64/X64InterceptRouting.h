#ifndef HOOKZZ_ARCH_X64_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_X64_INTERCEPT_ROUTING_H_

#include "hookzz_internal.h"

#include "AssemblyClosureTrampoline.h"

#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

class X64InterceptRouting : public InterceptRouting {
public:
  RoutingType branch_type_;

public:
  X64InterceptRouting(HookEntry *entry) : InterceptRouting(entry) {
  }

  void Active();

  virtual void *GetTrampolineTarget() = 0;

private:
  void Prepare();
};

#endif
