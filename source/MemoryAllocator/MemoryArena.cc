#include "MemoryAllocator/MemoryArena.h"

#include "dobby_internal.h"

std::vector<PageChunk *> MemoryArena::page_chunks;

void MemoryArena::Destroy(AssemblyCodeChunk *chunk) {
  return;
}

MemoryChunk *MemoryArena::AllocateChunk(int alloc_size, MemoryPermission permission) {
  MemoryChunk *result = nullptr;

  PageChunk *found_page = nullptr;
  for (auto *page : page_chunks) {
    if (page->permission == permission) {
      // check the page remain space is enough for the new chunk
      if ((page->cursor + alloc_size) < ((addr_t)page->mem.address + page->mem.length)) {
        found_page = page;
        break;
      }
    }
  }

  // alloc a new executable page
  if (!found_page) {
    int page_size = OSMemory::PageSize();
    void *page_addr = OSMemory::Allocate(NULL, page_size, permission);
    if (page_addr == NULL) {
      ERROR_LOG("Failed to alloc page");
      return NULL;
    }

    PageChunk *alloc_page = new PageChunk;
    alloc_page->mem.address = page_addr;
    alloc_page->mem.length = page_size;
    alloc_page->cursor = (addr_t)page_addr;
    alloc_page->permission = permission;
    MemoryArena::page_chunks.push_back(alloc_page);
    found_page = alloc_page;
  }

  if (found_page) {
    result = new MemoryChunk;
    result->address = (void *)found_page->cursor;
    result->length = alloc_size;

    // update page cursor
    found_page->chunks.push_back(result);
    found_page->cursor += alloc_size;
  }

  return result;
}

AssemblyCodeChunk *MemoryArena::AllocateCodeChunk(int alloc_size) {
  return MemoryArena::AllocateChunk(alloc_size, kReadExecute);
}

WritableDataChunk *MemoryArena::AllocateDataChunk(int alloc_size) {
  return MemoryArena::AllocateChunk(alloc_size, kReadWrite);
}
