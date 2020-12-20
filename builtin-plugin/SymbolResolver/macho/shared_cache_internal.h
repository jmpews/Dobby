#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#if defined(__LP64__)
typedef struct mach_header_64     mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64         section_t;
typedef struct nlist_64           nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header     mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section         section_t;
typedef struct nlist           nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#if __i386__
#define ARCH_NAME        "i386"
#define ARCH_CACHE_MAGIC "dyld_v1    i386"
#elif __x86_64__
#define ARCH_NAME          "x86_64"
#define ARCH_CACHE_MAGIC   "dyld_v1  x86_64"
#define ARCH_NAME_H        "x86_64h"
#define ARCH_CACHE_MAGIC_H "dyld_v1 x86_64h"
#elif __ARM_ARCH_7K__
#define ARCH_NAME        "armv7k"
#define ARCH_CACHE_MAGIC "dyld_v1  armv7k"
#elif __ARM_ARCH_7A__
#define ARCH_NAME        "armv7"
#define ARCH_CACHE_MAGIC "dyld_v1   armv7"
#elif __ARM_ARCH_7S__
#define ARCH_NAME        "armv7s"
#define ARCH_CACHE_MAGIC "dyld_v1  armv7s"
#elif __arm64e__
#define ARCH_NAME        "arm64e"
#define ARCH_CACHE_MAGIC "dyld_v1  arm64e"
#elif __arm64__
#if __LP64__
#define ARCH_NAME        "arm64"
#define ARCH_CACHE_MAGIC "dyld_v1   arm64"
#else
#define ARCH_NAME        "arm64_32"
#define ARCH_CACHE_MAGIC "dyld_v1arm64_32"
#endif
#endif

typedef uintptr_t addr_t;

bool is_addr_in_dyld_shared_cache(addr_t addr, size_t length);

void get_shared_cache_symbol_table(void *image_header, uintptr_t *nlist_array, char **string_pool,
                                   uint32_t *nlist_count);
