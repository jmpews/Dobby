#define MAX_STATIC_HOOK_ENTRY 64

#include <stdint.h>

typedef struct _InterceptorStatic {
  uint64_t this_;
  uint64_t count;
  uint64_t entry[MAX_STATIC_HOOK_ENTRY];
} InterceptorStatic;

typedef struct _HookEntryStatic {
  uint64_t function;
  uint64_t relocated_origin_function;
  uint64_t *trampoline_target_stub;
} HookEntryStatic;
