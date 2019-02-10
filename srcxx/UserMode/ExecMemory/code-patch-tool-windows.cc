#include <core/arch/Cpu.h>

#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "PlatformInterface/Common/Platform.h"

using namespace zz;

_MemoryOperationError CodePatch(void *address, void *buffer, int size) {

  return kMemoryOperationSuccess;
}
