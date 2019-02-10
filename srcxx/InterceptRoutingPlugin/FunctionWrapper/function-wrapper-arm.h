#ifndef FUNCTION_WRAPPER_ARM64_H_
#define FUNCTION_WRAPPER_ARM64_H_

#include "hookzz_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

class FunctionWrapperRouting : public InterceptRouting {
public:
  FunctionWrapperRouting(HookEntry *entry) : FunctionWrapperRouting(entry) {
  }

  virtual void Commit();

private:
  virtual void Prepare();

  virtual void Active();

  void BuildPreCallRouting();

  void BuildPostCallRouting();
};

#endif
