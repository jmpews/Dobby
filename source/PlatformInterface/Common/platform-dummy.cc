#include "macros.h"
#include "logging/check_logging.h"
#include "PlatformInterface/Common/Platform.h"

#include "UnifiedInterface/StdMemory.h"

#include <stdio.h>

namespace zz {

int GetProtectionFromMemoryPermission(MemoryPermission access) {
  return 0;
}

int GetFlagsForMemoryPermission(MemoryPermission access) {
  int flags = 0;
  return flags;
}

void *Allocate(void *address, int size, MemoryPermission access) {
  int prot  = GetProtectionFromMemoryPermission(access);
  int flags = GetFlagsForMemoryPermission(access);
  return nullptr;
}

int OSMemory::PageSize() {
  return 0;
}

void *OSMemory::Allocate(void *address, int size, MemoryPermission access) {
  int page_size    = OSMemory::PageSize();
  int request_size = size;
  void *result     = zz::Allocate(address, request_size, access);
  if (result == nullptr)
    return nullptr;

  // TODO: if need align
  void *aligned_base = result;
  return static_cast<void *>(aligned_base);
}

// static
bool OSMemory::Free(void *address, const int size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());
  DCHECK_EQ(0, 0);

  return 0;
}

bool OSMemory::Release(void *address, int size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % PageSize());
  DCHECK_EQ(0, size % PageSize());

  return 0;
}

bool OSMemory::SetPermissions(void *address, int size, MemoryPermission access) {
  DCHECK_EQ(0, size % PageSize());

  int prot = GetProtectionFromMemoryPermission(access);
  return 0;
}

// =====

void OSPrint::Print(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}

void OSPrint::VPrint(const char *format, va_list args) {
#if defined(ANDROID) && !defined(ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
#else
  vprintf(format, args);
#endif
}
} // namespace zz
