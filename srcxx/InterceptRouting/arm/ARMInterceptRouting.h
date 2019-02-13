#ifndef HOOKZZ_ARCH_ARM_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_ARM_INTERCEPT_ROUTING_H_

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "InterceptRouting/InterceptRouting.h"
#include "Interceptor.h"
#include "hookzz_internal.h"

class InterceptRouting : public InterceptRoutingBase {
public:
  // trampoline branch type
  enum RoutingType { ARM_B_Branch, ARM_LDR_Branch, Thumb1_B_Branch, Thumb2_B_Branch, Thumb2_LDR_Branch };

  // execute arm instruction or thumb instruction
  enum ExecuteState { ARMExecuteState, ThumbExecuteState };

  InterceptRouting(HookEntry *entry) : InterceptRoutingBase(entry) {
  }

  void Active();

  virtual void *GetTrampolineTarget() = 0;

  void Prepare();

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
};

#endif
