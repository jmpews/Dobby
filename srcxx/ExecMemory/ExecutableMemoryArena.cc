#include "stdcxx/LiteIterator.h"

#ifdef __APPLE__
#include "core/platform/platform-darwin/mach_vm.h"
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#endif

#include "ExecMemory/ExecutableMemoryArena.h"
#include "ExecMemory/PageAllocator.h"
#include "core/platform/platform.h"

using namespace zz;

LiteMutableArray ExecutableMemoryArena::page_chunks;

AssemblyCodeChunk *ExecutableMemoryArena::AllocateCodeChunk(int inSize) {
  void *result                 = NULL;
  ExecutablePage *page         = NULL;
  AssemblyCodeChunk *codeChunk = NULL;

  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(&page_chunks);
  while (page = reinterpret_cast<ExecutablePage *>(iter->getNextObject())) {
    if ((uintptr_t)page->cursor + inSize < page->capacity) {
      break;
    }
  }

  // alloc a new executable page.
  if (!page) {
    int page_size           = OSMemory::PageSize();
    void *page_address      = PageAllocator::Allocate(MemoryPermission::kReadExecute);
    ExecutablePage *newPage = new ExecutablePage;
    newPage->address        = page_address;
    newPage->cursor         = NULL;
    newPage->capacity       = page_size;
    ExecutableMemoryArena::page_chunks.pushObject(reinterpret_cast<LiteObject *>(newPage));
    page = newPage;
  }

  if (page) {
    codeChunk          = new AssemblyCodeChunk;
    codeChunk->address = page->cursor;
    codeChunk->size    = inSize;
    page->code_chunks.pushObject(reinterpret_cast<LiteObject *>(codeChunk));
  }

  return codeChunk;
}

// UserMode
// Search code cave from MemoryLayout
// MemoryRegion *CodeChunk::SearchCodeCave(uword pos, uword range_size, size_t size) {}