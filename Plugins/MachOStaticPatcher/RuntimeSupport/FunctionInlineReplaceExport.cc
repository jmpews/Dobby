
#include "InterfaceInternal.h"

static InterceptorStatic *FindInterceptorInImage(const char *image_name) {
  void *result    = NULL;
  int image_count = _dyld_image_count();

  for (size_t i = 0; i < image_count; i++) {
    mach_header_t *header = (mach_header_t *)_dyld_get_image_header(i);
    const char *name_                = _dyld_get_image_name(i);
    if (!name_)
      continue;
    name_ = strrchr(name_, '/') + 1;
    if (image_name != NULL && strcmp(image_name, name_))
      continue;
    
    // try to rebase the image.
    intptr_t vmslide = _dyld_get_image_vmaddr_slide(i);
    rebase_stub((const struct mach_header *)header, vmslide);
    
    // get the segment zDATA content
    void *content = getRuntimeSegmentContent((mach_header_t *)_dyld_get_image_header(i), "__zDATA");
    return (InterceptorStatic *)content;
  }

  return NULL;
}

static HookEntryStatic *FindFunctionEntry(InterceptorStatic *interceptor, void *function_virtual_address) {
  if (interceptor->this_) {
    // iterate all entry
    for (int i = 0; i < interceptor->count; i++) {
      HookEntryStatic *entry = reinterpret_cast<HookEntryStatic *>((uint64_t)interceptor->entry[i]);
      if (entry->function == (uint64_t)function_virtual_address) {
        return entry;
      }
    }
  }
  return NULL;
}

void ZzReplaceStatic(char *image_name, void *function_virtual_address, void *replace_call, void **origin_call) {
  InterceptorStatic *interceptor = FindInterceptorInImage(image_name);
  if (!interceptor)
    return;
  HookEntryStatic *entry = FindFunctionEntry(interceptor, function_virtual_address);
  if (!entry)
    return;
  *(entry->trampoline_target_stub) = (uint64_t)replace_call;
  *origin_call                     = (void *)entry->relocated_origin_function;
}
