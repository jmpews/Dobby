#include "hookzz_internal.h"

void set_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address) {
  *reinterpret_cast<void **>(&reg_ctx->general.regs.r12) = address;
}

void get_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address) {
}
