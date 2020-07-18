#include "dobby_internal.h"

void set_routing_bridge_next_hop(RegisterContext *ctx, void *address) {
  *reinterpret_cast<void **>(&ctx->general.regs.x16) = address;
}

void get_routing_bridge_next_hop(RegisterContext *ctx, void *address) {
}
