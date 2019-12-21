#include "PlatformInterface/Common/Platform.h"
#include "logging/check_logging.h"
#include "macros.h"

#include "UnifiedInterface/StdMemory.h"

#include <stdio.h>

#include "MachOManipulator/MachOManipulator.h"

extern MachoManipulator *mm;

namespace zz {

int OSMemory::PageSize() {
  return 0x4000;
}

void *OSMemory::Allocate(void *address, int size, MemoryPermission access) {
  void *result = NULL;
  if (access == kReadExecute) {
//    void *content = mm->getSegmentContent("__zTEXT");
//    return content;
    segment_command_t *zTEXT = mm->getSegment("__zTEXT");
    return (void *)zTEXT->vmaddr;
  } else if (access == kReadWrite) {
    segment_command_t *zDATA = mm->getSegment("__zDATA");
    return (void *)zDATA->vmaddr;
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
