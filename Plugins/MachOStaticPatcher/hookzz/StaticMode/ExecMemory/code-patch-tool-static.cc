#include "PlatformInterface/ExecMemory/CodePatchTool.h"
#include "PlatformInterface/Common/Platform.h"

#include "macros.h"

#include <string.h>
#include <stdlib.h>

#include <sys/mman.h>

#include <LIEF/MachO.hpp>

using namespace LIEF;

extern MachO::Binary *binary;

// the VirtualAddress is Allocate form OSMemory
_MemoryOperationError CodePatch(void *virtualAddress, void *buffer, int size) {
  MachO::SegmentCommand *zTEXT = binary->get_segment("__zTEXT");
  int offset = (addr_t)virtualAddress - (addr_t)zTEXT->virtual_address();
  
  // map the segment data -> mmap page
  std::vector<uint8_t> content = zTEXT->content();
  addr_t zTEXTPage = (addr_t)mmap(0, 0x4000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 255, 0);
  memcpy((void *)zTEXTPage, &content[0], content.size());

  // patch the buffer
  memcpy((void *)(zTEXTPage + offset), buffer, size);
  
  // map to the origin segmeng
  std::vector<uint8_t> rewrite_content((uint8_t *)zTEXTPage, (uint8_t *)(zTEXTPage+0x4000));
  zTEXT->content(rewrite_content);
  
  return kMemoryOperationSuccess;
}
