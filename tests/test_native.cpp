#include "dobby.h"

#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>

#define LOG(fmt, ...) printf("[test_native] " fmt "\n", ##__VA_ARGS__)

install_hook_name(dlopen, void *, const char *path, int mode) {
  LOG("dlopen: %s", path);
  return orig_dlopen(path, mode);
}

uint64_t get_arg(DobbyRegisterContext *ctx, int index) {
#if defined(_M_X64) || defined(__x86_64__)
  assert(index < 6);
  if (index == 0)
    return ctx->general.regs.rdi;
  if (index == 1)
    return ctx->general.regs.rsi;
  if (index == 2)
    return ctx->general.regs.rdx;
  if (index == 3)
    return ctx->general.regs.rcx;
  if (index == 4)
    return ctx->general.regs.r8;
  if (index == 5)
    return ctx->general.regs.r9;
#elif defined(__arm64__) || defined(__aarch64__)
  assert(index < 8);
  return ctx->general.regs.x[index];
#else
#error "Not support this architecture"
#endif
  return -1;
}

void test_dlopen() {
  LOG("test dlopen");

  {
    auto sym_addr = DobbySymbolResolver("dyld", "_dlopen");
    LOG("dlopen: %p", sym_addr);
    install_hook_dlopen(sym_addr);
  }

  dlopen("libtest.so", RTLD_LAZY);

  return;
}

void test_execve() {
  char *argv[] = {NULL};
  char *envp[] = {NULL};

  LOG("test execve");

  {
    auto sym_addr = DobbySymbolResolver(NULL, "_execve");
    LOG("execve: %p", sym_addr);
    DobbyInstrument(sym_addr, [](void *, DobbyRegisterContext *ctx) {
      auto path = (char *)get_arg(ctx, 0);
      LOG("execve: %s", path);
      return;
    });
  }

  execve("ls", argv, envp);

  return;
}

void test_end() {
  LOG("test end");
}

int main(int argc, char *argv[]) {
  test_execve();

  test_dlopen();

  test_end();

  return 0;
}
