#ifndef FUNCTION_WRAPPER_X64_H_
#define FUNCTION_WRAPPER_X64_H_

#include "hookzz_internal.h"

#include "AssemblyClosureTrampoline.h"
#include "InterceptRouting.h"
#include "Interceptor.h"
#include "intercept_routing_handler.h"

#include "InterceptRouting/x64/X64InterceptRouting.h"

class FunctionInlineReplaceRouting : public X64InterceptRouting {
public:
  FunctionInlineReplaceRouting(HookEntry *entry) : X64InterceptRouting(entry) {}

  void *GetTrampolineTarget();

private:
  virtual void BuildReplaceRouting();
};

#endif
