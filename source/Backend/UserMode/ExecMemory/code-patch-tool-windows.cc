#include "dobby/dobby_internal.h"

#include <windows.h>

using namespace zz;

PUBLIC int DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
  DWORD oldProtect;
  int page_size;

  // Get page size
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  page_size = si.dwPageSize;

  void *addressPageAlign = (void *)ALIGN(address, page_size);

  if (!VirtualProtect(addressPageAlign, page_size, PAGE_EXECUTE_READWRITE, &oldProtect))
    return -1;

  memcpy(address, buffer, buffer_size);

  if (!VirtualProtect(addressPageAlign, page_size, oldProtect, &oldProtect))
    return -1;

  return 0;
}
