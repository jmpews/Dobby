#ifndef HOOKZZ_ARCH_ARM64_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_ARM64_INTERCEPT_ROUTING_H_

#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"

#include "InterceptRouting/InterceptRouting.h"
#include "Interceptor.h"

class InterceptRouting : public InterceptRoutingBase {
public:
  RoutingType branch_type_;

public:
  // trampoline branch type
  enum RoutingType {
    ARM64_B_Branch,
    ARM64_LDR_Branch,
  };

  InterceptRouting(HookEntry *entry) : InterceptRoutingBase(entry) {
  }

  void Active();

  virtual void *GetTrampolineTarget() = 0;

  void Prepare();

private:
};

#endif
