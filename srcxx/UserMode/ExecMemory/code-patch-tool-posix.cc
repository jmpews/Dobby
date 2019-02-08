#include <core/arch/Cpu.h>

#include "ExecMemory/CodePatchTool.h"
#include "PlatformInterface/Common/Platform.h"

using namespace zz;

_MemoryOperationError CodePatch(void *address, void *buffer, int size) {

  int page_size = (int)sysconf(_SC_PAGESIZE);

  int page_size                = OSMemory::PageSize();
  uintptr_t page_align_address = ALIGN_FLOOR(address, page_size);
  int offset                   = (uintptr_t)address - page_align_address;

#if defined(__ANDROID__) || defined(__linux__)

  mprotect((void *)page_address, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
  memcpy((void *)((uintptr_t)page_address + offset), buffer, size);
  mprotect((void *)page_address, page_size, PROT_READ | PROT_EXEC);
#endif

  CpuFeatures::FlushICache((void *)((uintptr_t)page_address + offset), size);

  return kMemoryOperationSuccess;
}
