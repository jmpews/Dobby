#include "intercept_routing_handler.h"

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

// Use r12 as the next hop address
void set_prologue_routing_next_hop(RegisterContext *reg_ctx, void *address) {
  *reinterpret_cast<void **>(&reg_ctx->general.regs.r12) = address;
}

// Use r12 as the next hop address
void set_epilogue_routing_next_hop(RegisterContext *reg_ctx, void *address) {
  *reinterpret_cast<void **>(&reg_ctx->general.regs.r12) = address;
}
