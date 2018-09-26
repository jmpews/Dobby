#ifndef HOOKZZ_ARCH_ARM_INTERCEPT_ROUTING_H_
#define HOOKZZ_ARCH_ARM_INTERCEPT_ROUTING_H_

#include "hookzz_internal.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "Logging.h"
#include "AssemblyClosureTrampoline.h"
#include "intercept_routing_handler.h"

class ARMInterceptRouting : public InterceptRouting {
public:
  // trampoline branch type
  enum RoutingType { ARM_B_Branch, ARM_LDR_Branch, Thumb1_B_Branch, Thumb2_B_Branch, Thumb2_LDR_Branch };

  // execute arm instruction or thumb instruction
  enum ExecuteState { ARMExecuteState, ThumbExecuteState };

  ARMInterceptRouting(HookEntry *entry) : InterceptRouting(entry) {
  }

  virtual void Commit();

private:
  virtual void Prepare();

  virtual void Active();

  virtual void BuildFastForwardTrampoline();

  virtual void BuildPreCallRouting();

  virtual void BuildDynamicBinaryInstrumentationRouting();

  virtual void BuildPostCallRouting();

private:
  RoutingType branch_type_;
  ExecuteState execute_state_;
};

#endif
