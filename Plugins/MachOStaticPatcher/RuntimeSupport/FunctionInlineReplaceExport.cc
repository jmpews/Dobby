
#include "hookzz_static.h"

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <stdint.h>
#include <stdio.h>

#include <mach/vm_map.h>
#include <mach/mach.h>

#include <string.h>

#if defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

extern "C" {
  extern void *getSegmentContent(mach_header_t *header, char *segName);
}

InterceptorStatic *FindInterceptorInImage(const char *image_name) {
  void *result    = NULL;
  int image_count = _dyld_image_count();

  for (size_t i = 0; i < image_count; i++) {
    const struct mach_header *header = _dyld_get_image_header(i);
    const char *name_                = _dyld_get_image_name(i);
    if (!name_)
      continue;
    name_ = strrchr(name_, '/') + 1;
    if (image_name != NULL && strcmp(image_name, name_))
      continue;
    void *content = getSegmentContent((mach_header_t *)_dyld_get_image_header(i), "__zDATA");
    return (InterceptorStatic *)content;
  }

  return NULL;
}

HookEntryStatic *FindFunctionEntry(InterceptorStatic *interceptor, void *function_virtual_address) {
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
