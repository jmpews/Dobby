#include "core/arch/Cpu.h"

#include "dobby_internal.h"

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#if !defined(__APPLE__)
_MemoryOperationError CodePatch(void *address, void *buffer, int size) {

  int page_size                = (int)sysconf(_SC_PAGESIZE);
  uintptr_t page_align_address = ALIGN_FLOOR(address, page_size);
  int offset                   = (uintptr_t)address - page_align_address;

#if defined(__ANDROID__) || defined(__linux__)

  mprotect((void *)page_align_address, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
  memcpy((void *)((addr_t)page_align_address + offset), buffer, size);
  mprotect((void *)page_align_address, page_size, PROT_READ | PROT_EXEC);
#endif

  addr_t clear_start_ = (addr_t)page_align_address + offset;
  ClearCache((void *)clear_start_, (void *)(clear_start_ + size));

  return kMemoryOperationSuccess;
}

#endif