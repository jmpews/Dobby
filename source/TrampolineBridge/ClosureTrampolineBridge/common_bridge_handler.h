#pragma once

#include "dobby/dobby_internal.h"

#include "Interceptor.h"
#include "TrampolineBridge/ClosureTrampolineBridge/ClosureTrampoline.h"

inline asm_func_t closure_bridge_addr = nullptr;

void closure_bridge_init();

void get_routing_bridge_next_hop(DobbyRegisterContext *ctx, void *address);

void set_routing_bridge_next_hop(DobbyRegisterContext *ctx, void *address);

PUBLIC extern "C" inline void common_closure_bridge_handler(DobbyRegisterContext *ctx, ClosureTrampoline *tramp) {
  typedef void (*routing_handler_t)(Interceptor::Entry *, DobbyRegisterContext *);
  auto routing_handler = (routing_handler_t)features::apple::arm64e_pac_strip_and_sign(tramp->carry_handler);
  routing_handler((Interceptor::Entry *)tramp->carry_data, ctx);
  return;
}
