
#ifndef PLATFORM_INTERFACE_CODE_PATCH_TOOL_H
#define PLATFORM_INTERFACE_CODE_PATCH_TOOL_H

#include "PlatformUnifiedInterface/StdMemory.h"

MemoryOperationError CodePatch(void *address, void *buffer, int size);

#endif