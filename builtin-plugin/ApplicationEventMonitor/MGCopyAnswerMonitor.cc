#include "./dobby_monitor.h"

#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>

void common_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  CFStringRef key_ = 0;
  key_             = getCallFirstArg(reg_ctx);

  char str_key[256] = {0};
  CFStringGetCString(key_, str_key, 256, kCFStringEncodingUTF8);
  printf("MGCopyAnswer: %s", str_key);
}

__attribute__((constructor)) static void ctor() {
  void *lib               = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
  void *MGCopyAnswer_addr = dlsym(lib, "MGCopyAnswer");

  dobby_enable_near_branch_trampoline();
  DobbyInstrument((void *)MGCopyAnswer_addr, common_handler);
  return;
}