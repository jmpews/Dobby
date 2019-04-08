
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
void *getSegmentContent(mach_header_t *header, char *segName);
}

// =====

#define MAX_STATIC_HOOK_ENTRY 64

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
