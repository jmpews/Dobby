#define MAX_STATIC_HOOK_ENTRY 64

typedef struct _InterceptorStatic {
  void *this_;
  int count;
  uint64_t entry[MAX_STATIC_HOOK_ENTRY];
} InterceptorStatic;

typedef struct _HookEntryStatic {
  int function_offset;
  uint64_t relocated_origin_function;
  uint64_t *trampoline_target_stub;
} HookEntryStatic;
