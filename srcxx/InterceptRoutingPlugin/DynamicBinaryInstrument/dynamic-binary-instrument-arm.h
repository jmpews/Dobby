#ifndef FUNCTION_WRAPPER_ARM_H_
#define FUNCTION_WRAPPER_ARM_H_

#include "hookzz_internal.h"

#include "AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

class DynamicBinaryInstrumentRouting : public InterceptRouting {
public:
  DynamicBinaryInstrumentRouting(HookEntry *entry) : DynamicBinaryInstrumentRouting(entry) {
  }

  virtual void Commit();

private:
  virtual void Prepare();

  virtual void Active();

  virtual void BuildDynamicBinaryInstrumentRouting();
};

#endif
