#ifndef HOOKZZ_ARCH_ARM64_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_ARM64_INTERCEPT_ROUTING_H_

#include "AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "Logging.h"
#include "hookzz_internal.h"
#include "intercept_routing_handler.h"

#include "vm_core_extra/code-page-chunk.h"
#include "vm_core_extra/custom-code.h"

class ARM64InterceptRouting : public InterceptRouting {
public:
  // trampoline branch type
  enum RoutingType {
    ARM64_B_Branch,
    ARM64_LDR_Branch,
  };

  ARM64InterceptRouting(HookEntry *entry) : InterceptRouting(entry) {}

  virtual void Commit();

private:
  virtual void Prepare();

  virtual void Active();

  virtual void BuildFastForwardTrampoline();

  virtual void BuildReplaceRouting();

  virtual void BuildPreCallRouting();

  virtual void BuildDynamicBinaryInstrumentationRouting();

  virtual void BuildPostCallRouting();

private:
  RoutingType branch_type_;

  MemoryRegion *fast_forward_region;
};

#endif
