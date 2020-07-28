# Getting Started

## replace hook function

```
extern "C" {
  extern int DobbyHook(void *function_address, void *replace_call, void **origin_call);
}

size_t (*origin_fread)(void * ptr, size_t size, size_t nitems, FILE * stream);

size_t (fake_fread)(void * ptr, size_t size, size_t nitems, FILE * stream) {
    // Do What you Want.
    return origin_fread(ptr, size, nitems, stream);
}

DobbyHook((void *)fread, (void *)fake_fread, (void **)&origin_fread);
```

## instrument function

```

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

void format_integer_manually(char *buf, uint64_t integer) {
  int tmp = 0;
  for (tmp = integer; tmp > 0; tmp = (tmp >> 4)) {
    buf += (tmp % 16);
    buf--;
  }
}

// [ATTENTION]:
// printf will call 'malloc' internally, and will crash in a loop.
// so, use 'puts' is a better choice.
void malloc_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  size_t size_ = 0;
  size_        = getCallFirstArg(reg_ctx);
  char *buffer = "[-] function malloc first arg: 0x00000000.\n";
  format_integer_manually(strchr(buffer, '.') - 1, size_);
  puts(buffer);
}

DobbyInstrument((void *)malloc, malloc_handler)
```

## Android Linker Restriction

```
# impl at SymbolResolver/elf/dobby_symbol_resolver.cc
void *__loader_dlopen = DobbySymbolResolver(NULL, "__loader_dlopen");
DobbyHook((void *)__loader_dlopen, (void *)fake_loader_dlopen, (void **)&orig_loader_dlopen);
```

```
# impl at AndroidRestriction/android_restriction.cc
linker_disable_namespace_restriction();
void *handle = NULL;
handle       = dlopen(lib, RTLD_LAZY);
vm           = dlsym(handle, "_ZN7android14AndroidRuntime7mJavaVME");
```