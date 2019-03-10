#define MAX_STATIC_HOOK_ENTRY 64

typedef struct _InterceptorStatic {
  void *this_;
  int count;
  uintptr_t entry[MAX_STATIC_HOOK_ENTRY];
} InterceptorStatic;

typedef struct _HookEntryStatic {
  int function_offset;
  void *relocated_origin_function;
  uintptr_t *trampoline_target_stub;
} HookEntryStatic;
