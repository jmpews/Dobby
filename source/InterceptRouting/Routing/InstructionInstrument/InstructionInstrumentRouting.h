#pragma once

#include "dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"

#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

class InstructionInstrumentRouting : public InterceptRouting {
public:
  InstructionInstrumentRouting(HookEntry *entry, instrument_callback_t handler) : InterceptRouting(entry) {
    this->handler = handler;
  }

  void DispatchRouting();

public:
  instrument_callback_t handler;

private:
  virtual void BuildRouting();

private:
  void *prologue_dispatch_bridge;
};
