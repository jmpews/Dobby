#pragma once

#include "dobby/dobby_internal.h"

extern "C" void instrument_routing_dispatch(Interceptor::Entry *entry, DobbyRegisterContext *ctx);

struct ClosureTrampoline : Trampoline {
  void *carry_data;
  void *carry_handler;

  ClosureTrampoline(int type, CodeMemBlock buffer, void *carry_data, void *carry_handler) : Trampoline(type, buffer) {
    this->carry_data = carry_data;
    this->carry_handler = carry_handler;
  }
};

ClosureTrampoline *GenerateClosureTrampoline(void *carry_data, void *carry_handler);

inline ClosureTrampoline *GenerateInstrumentClosureTrampoline(Interceptor::Entry *entry) {
  auto handler = (void *)instrument_routing_dispatch;
  features::apple::arm64e_pac_strip(handler);
  return GenerateClosureTrampoline(entry, handler);
}