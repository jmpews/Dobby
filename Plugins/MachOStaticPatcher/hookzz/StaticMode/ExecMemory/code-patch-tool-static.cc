#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "PlatformInterface/Common/Platform.h"

#include "macros.h"

#include <string.h>
#include <stdlib.h>

#if 0
#include <sys/mman.h>
#endif

#include "MachOManipulator/MachOManipulator.h"


extern MachoManipulator *mm;

// the VirtualAddress is Allocate form OSMemory
_MemoryOperationError CodePatch(void *virtualAddress, void *buffer, int size) {
    segment_command_t *zTEXT = mm->getSegment("__zTEXT");
  int offset = (addr_t)virtualAddress - (addr_t)zTEXT->vmaddr;
  
#if 0
  // map the segment data -> mmap page
  void *content = mm->getSegmentContent("__zTEXT");
#if 0
  addr_t zTEXTPage = (addr_t)mmap(0, zTEXT->size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 255, 0);
#else
  addr_t zTEXTPage = (addr_t)malloc(zTEXT->vmsize);
#endif

  memcpy((void *)zTEXTPage, content, zTEXT->vmsize);
  // patch the buffer
  memcpy((void *)(zTEXTPage + offset), buffer, size);
#endif
  
  return kMemoryOperationSuccess;
}
