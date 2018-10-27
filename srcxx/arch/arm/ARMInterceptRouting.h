#ifndef HOOKZZ_ARCH_ARM_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_ARM_INTERCEPT_ROUTING_H_

#include "AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "Logging.h"
#include "hookzz_internal.h"
#include "intercept_routing_handler.h"

#include "vm_core_extra/code-page-chunk.h"
#include "vm_core_extra/custom-code.h"

class ARMInterceptRouting : public InterceptRouting {
public:
  // trampoline branch type
  enum RoutingType { ARM_B_Branch, ARM_LDR_Branch, Thumb1_B_Branch, Thumb2_B_Branch, Thumb2_LDR_Branch };

  // execute arm instruction or thumb instruction
  enum ExecuteState { ARMExecuteState, ThumbExecuteState };

  ARMInterceptRouting(HookEntry *entry) : InterceptRouting(entry) {}

  virtual void Commit();

private:
  virtual void Prepare();

  virtual void Active();

  virtual void BuildFastForwardTrampoline();

  virtual void BuildReplaceRouting();

  virtual void BuildPreCallRouting();

  virtual void BuildDynamicBinaryInstrumentationRouting();

  virtual void BuildPostCallRouting();

  // private for thumb & arm
private:
  void prepare_arm();

  void prepare_thumb();

  // active arm routing
  void active_arm_intercept_routing();

  // active thumb routing
  void active_thumb_intercept_routing();

private:
  int relocate_size;

  RoutingType branch_type_;

  ExecuteState execute_state_;

  MemoryRegion *fast_forward_region;
};

#endif
