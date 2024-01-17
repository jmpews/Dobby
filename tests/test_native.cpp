#include "dobby.h"

#include <unistd.h>
#include <stdio.h>

#include <dlfcn.h>

#define LOG(fmt, ...) printf("[test_native] " fmt "\n", ##__VA_ARGS__)

install_hook_name(dlopen, void *, const char *path, int mode) {
  LOG("dlopen: %s", path);
  return orig_dlopen(path, mode);
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
      LOG("execve: %s", (char *)ctx->general.regs.x0);
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
