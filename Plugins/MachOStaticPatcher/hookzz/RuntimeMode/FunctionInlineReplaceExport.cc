#define MAX_STATIC_HOOK_ENTRY 64

typedef struct _InterceptorStatic {
  void *this;
  int count;
  uintptr_t entry[MAX_STATIC_HOOK_ENTRY];
} InterceptorStatic;

typedef struct _HookEntryStatic {
  void *function_address;
  void *relocated_origin_function;
  uintptr_t *trampoline_target_stub;
} HookEntryStatic;

void *getSegmentContent(mach_header *header, char *name) {
}

mach_header *SearchImageInProcess(char *image_name) {
  mach_header *header = _dyld_get_image_header(0);
  void *zDATA         = getSegmentContent("__zDATA");
  return header;
}

void translateStaticToRuntime(InterceptorStatic *interceptor_static, void *function_address, void *trampoline_target,
                              void **relocated_origin_function) {
  for (int i = 0; i < interceptor_static->count; i++) {
    HookEntryStatic *entry_static = reinterpret_cast<HookEntryStatic *>(interceptor_static->entry[i] + slide);

    if (entry_static->function_address == function_address) {
      *(uintptr_t *)((addr_t)entry_static->trampoline_target_stub + slide) = trampoline_target;
      *relocated_origin_function = (void *)((addr_t)entry_static->relocated_origin_function + slide);
    }
  }
}

void ZzReplaceStatic(char *image_name, void *function_virtual_address, void *replace_call, void **origin_call) {
  mach_header *header = SearchImageInProcess(image_name);
  void *content       = getSegmentContent(header, "__zDATA");

  translateStaticToRuntime(content, function_virtual_address, replace_call, origin_call);
  return;
}
