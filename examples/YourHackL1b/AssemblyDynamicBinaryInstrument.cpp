//
// Created by jmpews on 2019/3/31.
//

#include "AssemblyDynamicBinaryInstrument.h"

#include <stdlib.h>
#include "hookzz.h"

uintptr_t getCallFirstArg(RegisterContext *reg_ctx) {
  uintptr_t result;
#if defined(_M_X64) || defined(__x86_64__)
#if defined(_WIN32)
  result = reg_ctx->general.regs.rcx;
#else
  result = reg_ctx->general.regs.rdi;
#endif
#elif defined(__arm64__) || defined(__aarch64__)
  result = reg_ctx->general.regs.x0;
#elif defined(__arm__)
  result = reg_ctx->general.regs.r0;
#else
#error "Not Support Architecture."
#endif
  return result;
}

void malloc_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  size_t size_ = 0;
  size_        = getCallFirstArg(reg_ctx);
}

void free_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  uintptr_t mem_ptr;
  mem_ptr = getCallFirstArg(reg_ctx);
}

__attribute__((constructor)) void ___main() {

  ZzDynamicBinaryInstrument((void *)malloc, malloc_handler);
  ZzDynamicBinaryInstrument((void *)free, free_handler);

  return;
}
