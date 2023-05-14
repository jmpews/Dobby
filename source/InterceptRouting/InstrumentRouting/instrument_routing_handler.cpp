#include "dobby/dobby_internal.h"
#include "TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.h"
#include "InterceptRouting/InstrumentRouting.h"
#include "logging/logging.h"

void instrument_forward_handler(Interceptor::Entry *entry, DobbyRegisterContext *ctx);

extern "C" void instrument_routing_dispatch(Interceptor::Entry *entry, DobbyRegisterContext *ctx) {
  // __FUNC_CALL_TRACE__();
  auto instrument_callback_fn = (dobby_instrument_callback_t)entry->pre_handler;
  if (instrument_callback_fn) {
    instrument_callback_fn((void *)entry->addr, ctx);
  }

  // set TMP_REG_0 to next hop
  set_routing_bridge_next_hop(ctx, (void *)entry->relocated.addr());
}
