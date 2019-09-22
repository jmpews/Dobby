
#ifndef ZZ_CODE_PATCH_TOOL_H_
#define ZZ_CODE_PATCH_TOOL_H_

#include "UnifiedInterface/StdMemory.h"

MemoryOperationError CodePatch(void *address, void *buffer, int size);

#endif