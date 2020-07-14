#include "./MemoryArena.h"

#include "dobby_internal.h"

LiteMutableArray *MemoryArena::page_chunks = NULL;

void MemoryArena::Destory(AssemblyCodeChunk *codeChunk) {
  return;
}

MemoryChunk *MemoryArena::AllocateChunk(int inSize, MemoryPermission permission) {
  MemoryChunk *result = NULL;

  if (!MemoryArena::page_chunks) {
    MemoryArena::page_chunks = new LiteMutableArray;
  }

  LiteCollectionIterator *iter = LiteCollectionIterator::withCollection(page_chunks);
  PageChunk *page              = NULL;
  while ((page = reinterpret_cast<PageChunk *>(iter->getNextObject())) != NULL) {
    if (page->permission == permission) {
      // check the page remain space is enough for the new chunk
      if ((page->page_cursor + inSize) < ((addr_t)page->page.address + page->page.length)) {
        break;
      }
    }
  }
  delete iter;

  // alloc a new executable page.
  if (!page) {
    int pageSize      = OSMemory::PageSize();
    void *pageAddress = OSMemory::Allocate(NULL, pageSize, permission);
    if (pageAddress == NULL) {
      LOG("Failed to alloc page");
      return NULL;
    }

    PageChunk *newPage    = new PageChunk;
    newPage->page.address = pageAddress;
    newPage->page.length  = pageSize;
    newPage->page_cursor  = (addr_t)pageAddress;
    newPage->permission = permission;
    newPage->chunks       = new LiteMutableArray(8);
    MemoryArena::page_chunks->pushObject(reinterpret_cast<LiteObject *>(newPage));
    page = newPage;
  }

  MemoryChunk *chunk = NULL;
  if (page) {
    chunk          = new MemoryChunk;
    chunk->address = (void *)page->page_cursor;
    chunk->length  = inSize;

    // update page cursor
    page->chunks->pushObject(reinterpret_cast<LiteObject *>(chunk));
    page->page_cursor += inSize;
  }

  result = chunk;
  return result;
}

AssemblyCodeChunk *MemoryArena::AllocateCodeChunk(int inSize) {
  return MemoryArena::AllocateChunk(inSize, kReadExecute);
}

WritableDataChunk *MemoryArena::AllocateDataChunk(int inSize) {
  return MemoryArena::AllocateChunk(inSize, kReadWrite);
}

// UserMode
// Search code cave from MemoryLayout
// MemoryRegion *CodeChunk::SearchCodeCave(uword pos, uword range, size_t size) {}
