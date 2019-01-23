#ifndef HOOKZZ_ARCH_ARM64_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_ARM64_INTERCEPT_ROUTING_H_

#include "hookzz_internal.h"

#include "AssemblyClosureTrampoline.h"

#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

class ARM64InterceptRouting : public InterceptRouting {
public:
  RoutingType branch_type_;

public:
  // trampoline branch type
  enum RoutingType {
    ARM64_B_Branch,
    ARM64_LDR_Branch,
  };

  ARM64InterceptRouting(HookEntry *entry) : InterceptRouting(entry) {
  }

  void Active();

  virtual void *GetTrampolineTarget() = 0;

private:
  void Prepare();
};

#endif
