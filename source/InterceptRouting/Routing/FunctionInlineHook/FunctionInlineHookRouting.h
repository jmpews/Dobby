#pragma once

#include "dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"

#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

class FunctionInlineHookRouting : public InterceptRouting {
public:
  FunctionInlineHookRouting(HookEntry *entry, dobby_dummy_func_t replace_func) : InterceptRouting(entry) {
    this->replace_func = replace_func;
  }

  void DispatchRouting() override;

private:
  virtual void BuildRouting();

private:
  dobby_dummy_func_t replace_func;
};
