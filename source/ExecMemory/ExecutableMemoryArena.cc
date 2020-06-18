#include "stdcxx/LiteIterator.h"

#include "ExecMemory/ExecutableMemoryArena.h"
#include "ExecMemory/PageAllocator.h"
#include "PlatformInterface/Common/Platform.h"

#include "logging/check_logging.h"

using namespace zz;

LiteMutableArray *ExecutableMemoryArena::page_chunks = NULL;

void ExecutableMemoryArena::Destory(AssemblyCodeChunk *codeChunk) {
  return;
}

AssemblyCodeChunk *ExecutableMemoryArena::AllocateCodeChunk(int inSize) {
  AssemblyCodeChunk *result = NULL, *codeChunk = NULL;
  ExecutablePage *page = NULL;

  if (!ExecutableMemoryArena::page_chunks) {
    ExecutableMemoryArena::page_chunks = new LiteMutableArray;
  }

  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(page_chunks);
  while ((page = reinterpret_cast<ExecutablePage *>(iter->getNextObject())) != NULL) {
    if (((addr_t)page->cursor + inSize) < ((addr_t)page->address + page->capacity)) {
      break;
    }
  }
  delete iter;

  // alloc a new executable page.
  if (!page) {
    int page_size      = OSMemory::PageSize();
    void *page_address = PageAllocator::Allocate(MemoryPermission::kReadExecute);
    CHECK_NOT_NULL(page_address);

    ExecutablePage *newPage = new ExecutablePage;
    newPage->address        = page_address;
    newPage->cursor         = newPage->address;
    newPage->capacity       = page_size;
    newPage->code_chunks    = new LiteMutableArray(8);
    ExecutableMemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
    page = newPage;
  }

  if (page) {
    codeChunk          = new AssemblyCodeChunk;
    codeChunk->address = page->cursor;
    codeChunk->size    = inSize;

    page->code_chunks->pushObject(reinterpret_cast<LiteObject *>(codeChunk));
    page->cursor = (void *)((addr_t)page->cursor + inSize);
  }

  result = codeChunk;
  return result;
}

// UserMode
// Search code cave from MemoryLayout
// MemoryRegion *CodeChunk::SearchCodeCave(uword pos, uword range_size, size_t size) {}
