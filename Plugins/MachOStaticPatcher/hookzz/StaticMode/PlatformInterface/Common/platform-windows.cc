#include "PlatformInterface/Common/Platform.h"
#include "logging/check_logging.h"
#include "macros.h"

#include "UnifiedInterface/StdMemory.h"

#include <stdio.h>

namespace zz {

int OSMemory::PageSize() {
  return 0x4000;
}

void *OSMemory::Allocate(void *address, int size, MemoryPermission access) {
  void *result;
  if (access = kReadExecute) {
    return Segment(HookZz, section(execMemoryPool));
  } else if (access = kReadWrite) {
    return Segment(HookZz, section(objectMemoryPool));
  } else {
    FATAL("Not Support the specific MemoryPermission!!!");
  }
  return 0
}

// static
bool OSMemory::Free(void *address, const int size) {
  return true;
}

bool OSMemory::Release(void *address, int size) {
  return true;
}

bool OSMemory::SetPermissions(void *address, int size, MemoryPermission access) {
  return true;
}

// =====

void OSPrint::Print(const char *format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}

void OSPrint::VPrint(const char *format, va_list args) {
  vprintf(format, args);
}
} // namespace zz
