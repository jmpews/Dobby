#include "MemoryAllocator/MemoryArena.h"

#include "dobby_internal.h"

MemBlock * MemoryArena::allocBlock(size_t alloc_size) {
    MemBlock *result;
    for (auto *chunk : chunks_) {
      result = chunk->allocBlock(alloc_size);
      if(result)
        return result;
    }

  auto allocNewChunk = [&](size_t new_alloc_size) -> MemChunk * {
    size_t chunk_size = ALIGN_CEIL(new_alloc_size, OSMemory::PageSize());
    addr_t chunk_addr = (addr_t)OSMemory::Allocate(chunk_size, kNoAccess);

    MemChunk *chunk = new MemChunk{.addr = chunk_addr, .cursor_addr = chunk_addr, .size = chunk_size};
    return chunk;
    };

  MemChunk *new_chunk = allocNewChunk(alloc_size);
  chunks_.push_back(new_chunk);

  result = new_chunk->allocBlock(alloc_size);
  return result;
}
