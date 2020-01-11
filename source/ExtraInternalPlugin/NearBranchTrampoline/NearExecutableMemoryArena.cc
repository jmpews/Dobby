#include "dobby_internal.h"

#include "./NearExecutableMemoryArena.h"

#include "ExtraInternalPlugin/NearBranchTrampoline/PlatformUtil/GetProcessMemoryLayout.h"

#include <iostream>
#include <vector>

using namespace zz;

#define KB (1024uLL)
#define MB (1024uLL * KB)
#define GB (1024uLL * MB)

LiteMutableArray *NearExecutableMemoryArena::page_chunks = NULL;

// Search code cave from MemoryLayout
void NearExecutableMemoryArena::PushMostNearCodePage(addr_t pos, int range_size) {
  std::vector<MemoryRegion> memory_layout = GetProcessMemoryLayout();
  addr_t memory_region_start              = 0;
  addr_t memory_region_end                = 0;
  addr_t pre_memory_region_end            = 0;
  addr_t next_memory_region_start         = 0;
  for (int i = 0; i < memory_layout.size(); i++) {

    memory_region_start = memory_layout[i].address;
    memory_region_end   = memory_region_start + memory_layout[i].length;
    if (memory_region_start < pos && memory_region_end > pos) {
      MemoryRegion *pre_memory_region  = &memory_layout[i - 1];
      MemoryRegion *next_memory_region = &memory_layout[i + 1];
      pre_memory_region_end            = pre_memory_region->address + pre_memory_region->length;
      next_memory_region_start         = next_memory_region->address;
      break;
    }
  }

  if (memory_region_start - pre_memory_region_end > (16 * MB))
    pre_memory_region_end = memory_region_start - (16 * MB);

  // add pages to list
  for (addr_t page_addr = pre_memory_region_end; page_addr < memory_region_start; page_addr += OSMemory::PageSize()) {
    void *page_address = OSMemory::Allocate((void *)page_addr, OSMemory::PageSize(), MemoryPermission::kReadExecute);
    ExecutablePage *newPage = new ExecutablePage;
    newPage->address        = page_address;
    newPage->cursor         = newPage->address;
    newPage->capacity       = OSMemory::PageSize();
    newPage->code_chunks    = new LiteMutableArray(8);
    NearExecutableMemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
  }
  DLOG("add near pages from %p - %p", pre_memory_region_end, memory_region_start);

  if (next_memory_region_start - memory_region_end > (16 * MB))
    next_memory_region_start = memory_region_end + (16 * MB);

  // add pages to list
  for (addr_t page_addr = memory_region_end; page_addr < next_memory_region_start; page_addr += OSMemory::PageSize()) {
    void *page_address = OSMemory::Allocate((void *)page_addr, OSMemory::PageSize(), MemoryPermission::kReadExecute);
    ExecutablePage *newPage = new ExecutablePage;
    newPage->address        = page_address;
    newPage->cursor         = newPage->address;
    newPage->capacity       = OSMemory::PageSize();
    newPage->code_chunks    = new LiteMutableArray(8);
    NearExecutableMemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
  }
  DLOG("add near pages from %p - %p", memory_region_end, next_memory_region_start);
}

AssemblyCodeChunk *NearExecutableMemoryArena::AllocateCodeChunk(int inSize, addr_t pos, size_t range_size) {
  void *result                 = NULL;
  ExecutablePage *page         = NULL;
  AssemblyCodeChunk *codeChunk = NULL;

  if (!NearExecutableMemoryArena::page_chunks) {
    NearExecutableMemoryArena::page_chunks = new LiteMutableArray;
  }

  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(page_chunks);
  while ((page = reinterpret_cast<ExecutablePage *>(iter->getNextObject())) != NULL) {
    if (llabs((intptr_t)((addr_t)page->cursor - pos)) < range_size) {
      if (((addr_t)page->cursor + inSize) < ((addr_t)page->address + page->capacity)) {
        break;
      }
    }
  }
  delete iter;

  if (!page) {
    NearExecutableMemoryArena::PushMostNearCodePage(pos, range_size);
    // try again
    NearExecutableMemoryArena::AllocateCodeChunk(inSize, pos, range_size);
  } else {
    codeChunk          = new AssemblyCodeChunk;
    codeChunk->address = page->cursor;
    codeChunk->size    = inSize;

    page->code_chunks->pushObject(reinterpret_cast<LiteObject *>(codeChunk));
    page->cursor = (void *)((addr_t)page->cursor + inSize);
    return codeChunk;
  }

  UNREACHABLE();
  return NULL;
}
