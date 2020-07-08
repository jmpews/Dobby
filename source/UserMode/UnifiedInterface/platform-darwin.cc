#include <errno.h>
#include <limits.h>
#include <pthread.h>

#include <sched.h> // for sched_yield
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#if defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h> // NOLINT, for sysctl
#endif

#include "dobby_internal.h"

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach/vm_statistics.h>
#endif

#include <string.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

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

namespace zz {

#if defined(__APPLE__)
const int kMmapFd = VM_MAKE_TAG(255);
#else
const int kMmapFd = -1;
#endif

const int kMmapFdOffset = 0;

static addr_t g_aarch64_b_source = 0;
void register_aarch64_b_source(addr_t address) {
  g_aarch64_b_source = address;
}

#include "MemoryArena.h"
#include <vector>

bool memory_chunk_comparator(MemoryChunk chunk_a, MemoryChunk chunk_b) {
  return (chunk_a.address > chunk_b.address);
}

std::vector<MemoryChunk *> ProcessMemoryMap;
void dump_process_memory_region() {
  if (!ProcessMemoryMap.empty()) {
    ProcessMemoryMap.clear();
  }

  struct vm_region_submap_short_info_64 submap_info;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  mach_vm_address_t addr       = 0;
  mach_vm_size_t size          = 0;
  natural_t depth              = 0;
  while (true) {
    count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    kern_return_t kr =
        mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth, (vm_region_recurse_info_t)&submap_info, &count);
    if (kr == KERN_INVALID_ADDRESS) {
      break;
    } else {
      KERN_RETURN_ASSERT(kr);
    }

    if (0 && submap_info.is_submap) {
      ++depth;
    } else {
      MemoryChunk *chunk = new MemoryChunk(addr, size);
      ProcessMemoryMap->push_back(chunk);
    }
  }

  std::sort(ProcessMemoryMap.begin(), ProcessMemoryMap.end(), memory_chunk_comparator);
}

addr_t catch_aarch64_b_xxx_availble_page() {
}

void *OSMemory::Allocate(void *address, int size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  int prot = GetProtectionFromMemoryPermission(access);

  void *result = NULL;

  addr_t image_start;
  addr_t image_end = get_macho_image_end(image_start);

  if (access == MemoryPermission::kReadExecute) {
    int offset_max = (1 << (26 - 1 + 2));
    for (int offset = 0; i < offset_max; i += OSMemory::PageSize()) {
      result = mmap(image_start - offset - OSMemory::PageSize(), size, prot, MAP_PRIVATE | MAP_FIXED, kMmapFd,
                    kMmapFdOffset);
      if (result != MAP_FAILED)
        break;

      result = mmap(image_end + offset, size, prot, MAP_PRIVATE | MAP_FIXED, kMmapFd, kMmapFdOffset);
      if (result != MAP_FAILED)
        break;
    }
  }

  result = mmap(address, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, kMmapFd, kMmapFdOffset);
  if (result == MAP_FAILED)
    return nullptr;

  // TODO: if need align

  void *aligned_base = result;
  return static_cast<void *>(aligned_base);
}

} // namespace zz
