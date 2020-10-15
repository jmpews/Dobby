#include "./dobby_monitor.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static uintptr_t getCallFirstArg(RegisterContext *reg_ctx) {
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

void format_integer_manually(char *buf, uint64_t integer) {
  int tmp = 0;
  for (tmp = (int)integer; tmp > 0; tmp = (tmp >> 4)) {
    buf += (tmp % 16);
    buf--;
  }
}

// [ATTENTION]:
// printf will call 'malloc' internally, and will crash in a loop.
// so, use 'puts' is a better choice.
void malloc_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  size_t size_  = 0;
  size_         = getCallFirstArg(reg_ctx);
  char *buffer_ = (char *)"[-] function malloc first arg: 0x00000000.\n";
  format_integer_manually(strchr(buffer_, '.') - 1, size_);
  puts(buffer_);
}

void free_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  uintptr_t mem_ptr;

  mem_ptr = getCallFirstArg(reg_ctx);

  char *buffer = (char *)"[-] function free first arg: 0x00000000.\n";
  format_integer_manually(strchr(buffer, '.') - 1, mem_ptr);
  puts(buffer);
}

__attribute__((constructor)) static void ctor() {
  //    DobbyInstrument((void *)mmap, malloc_handler);
  //    DobbyInstrument((void *)free, free_handler);
  return;
}
