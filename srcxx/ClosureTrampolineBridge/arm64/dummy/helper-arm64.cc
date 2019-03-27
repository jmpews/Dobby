#include "hookzz_internal.h"

void *get_func_ret_address(RegisterContext *reg_ctx) {
  void *ret_address = reinterpret_cast<void *>(reg_ctx->lr);
  return ret_address;
}

void set_func_ret_address(RegisterContext *reg_ctx, void *address) {
#if 1
  reg_ctx->lr = (uint64_t)address;
#else
  *reinterpret_cast<void **>(&reg_ctx->lr) = address;
#endif
}

void set_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address) {
  *reinterpret_cast<void **>(&reg_ctx->general.regs.x16) = address;
}

void get_routing_bridge_next_hop(RegisterContext *reg_ctx, void *address) {
}
