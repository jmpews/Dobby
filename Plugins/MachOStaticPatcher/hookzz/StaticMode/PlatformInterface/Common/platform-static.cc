#include "PlatformInterface/Common/Platform.h"
#include "logging/check_logging.h"
#include "macros.h"

#include "UnifiedInterface/StdMemory.h"

#include <stdio.h>

#include <LIEF/MachO.hpp>

using namespace LIEF;

MachO::Binary *binary;

namespace zz {

int OSMemory::PageSize() {
  return 0x4000;
}

void *OSMemory::Allocate(void *address, int size, MemoryPermission access) {
  void *result = NULL;
  if (access == kReadExecute) {
    MachO::SegmentCommand *zTEXT = binary->get_segment("__zTEXT");
    return (void *)zTEXT->virtual_address();
  } else if (access == kReadWrite) {
    MachO::SegmentCommand *zDATA = binary->get_segment("__zDATA");
    return (void *)zDATA->virtual_address();
  } else {
    FATAL("Not Support the specific MemoryPermission!!!");
  }
  return 0;
}

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
