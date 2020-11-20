#ifndef DYNAMIC_BINARY_INSTRUMENT_H
#define DYNAMIC_BINARY_INSTRUMENT_H

#include "dobby_internal.h"

#include "ClosureTrampolineBridge/AssemblyClosureTrampoline.h"
#include "InterceptRouting/InterceptRouting.h"
#include "Interceptor.h"

#define X64InterceptRouting   InterceptRouting
#define ARM64InterceptRouting InterceptRouting

class DynamicBinaryInstrumentRouting : public X64InterceptRouting {
public:
  DynamicBinaryInstrumentRouting(HookEntry *entry, void *handler) : X64InterceptRouting(entry) {
    this->handler = handler;
  }

  void Dispatch();

public:
  void *handler;

private:
  virtual void BuildDynamicBinaryInstrumentRouting();

private:
  void *prologue_dispatch_bridge;

  ;
};

#endif
