
#include "logging/logging.h"

#include "ClosureTrampolineBridge/closure-trampoline-common-handler/closure-trampoline-common-handler.h"

#if 0
void get_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address) {
}

void set_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address) {
}
#endif

// Closure bridge branch here unitily, then  common_bridge_handler will dispatch to other handler.
void intercept_routing_common_bridge_handler(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry) {
  HOOKZZ_DLOG("[*] catch common bridge handler, carry data: %p, carry handler: %p\n",
              ((HookEntry *)entry->carry_data)->target_address, entry->carry_handler);
  USER_CODE_CALL UserCodeCall = (USER_CODE_CALL)entry->carry_handler;
  UserCodeCall(reg_ctx, entry);
  return;
}