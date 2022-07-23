
#include "logging/logging.h"

#include "TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.h"

PUBLIC void common_closure_bridge_handler(DobbyRegisterContext *ctx, ClosureTrampolineEntry *entry) {
  DLOG(0, "common bridge handler: carry data: %p, carry handler: %p", (HookEntry *)entry->carry_data,
       entry->carry_handler);

  typedef void (*routing_handler_t)(HookEntry *, DobbyRegisterContext *);
  auto routing_handler = (routing_handler_t)entry->carry_handler;

#if __APPLE__ && __has_feature(ptrauth_calls)
  routing_handler = (typeof(routing_handler))ptrauth_sign_unauthenticated(
      (void *)routing_handler, ptrauth_key_asia, ptrauth_function_pointer_type_discriminator(typeof(routing_handler)));
#endif

  routing_handler((HookEntry *)entry->carry_data, ctx);
  return;
}
