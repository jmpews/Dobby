#include "stdcxx/LiteIterator.h"

#ifdef __APPLE__
#include "core/platform/platform-darwin/mach_vm.h"
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#endif

#include "ExecMemory/ExecutableMemoryArena.h"

using namespace zz;

LiteMutableArray ExecutableMemoryArena::page_chunks;

AssemblyCodeChunk *ExecutableMemoryArena::AllocateCodeChunk(int inSize) {
  void *result                 = NULL;
  ExecutablePage *page         = NULL;
  AssemblyCodeChunk *codeChunk = NULL;

  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(&page_chunks);
  while (page = static_cast<MemoryPage *>(iter->getNextObject())) {
    if (page->cursor + inSize < page->capacity) {
      break;
    }
  }

  // alloc a new executable page.
  if (!page) {
    int page_size           = OSMemory::PageSize();
    void *page_address      = PageAllocator::Allocate(MemoryPermission::kReadExecute);
    ExecutablePage *newPage = new ExecutablePage;
    newPage->address        = page_address;
    newpage->cursor         = NULL;
    newPage->capacity       = page_size;
    page_chunks->pushObject(static_cast<LiteObject *>(newPage));
    page = newPage;
  }

  if (page) {
    codeChunk          = new CodeChunk;
    codeChunk->address = page->cursor;
    codeChunk->size    = inSize;
    page->code_chunks->pushObject(static_cast<LiteObject *>(codeChunk));
  }

  return codeChunk;
}

// Search code cave from MemoryLayout
MemoryRegion *CodeChunk::SearchCodeCave(uword pos, uword range_size, size_t size) {}