#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "PlatformInterface/Common/Platform.h"

#include "macros.h"

#include <windows.h>

using namespace zz;

_MemoryOperationError CodePatch(void *address, void *buffer, int size) {
	DWORD oldProtect;
  int pageSize;

// Get page size
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  pageSize = si.dwPageSize;

  void *addressPageAlign = (void *)ALIGN(address, pageSize);
  

  if (!VirtualProtect(addressPageAlign, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    return kMemoryOperationError;

  memcpy(address, buffer, size);

   if (!VirtualProtect(addressPageAlign, pageSize, oldProtect, &oldProtect))
    return kMemoryOperationError;

  return kMemoryOperationSuccess;
}
