#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "PlatformInterface/Common/Platform.h"

#include "macros.h"

_MemoryOperationError CodePatch(void *address, void *buffer, int size) {
  memcpy(address, buffer, size);
}