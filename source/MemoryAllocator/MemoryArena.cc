#include "MemoryAllocator/MemoryArena.h"

#include "dobby_internal.h"

MemBlock * MemoryArena::allocBlock(size_t alloc_size) {
    MemBlock *result;
    for (auto *chunk : chunks_) {
      result = chunk->allocBlock(alloc_size);
      if(result)
        return result;
    }

  MemChunk *new_chunk = allocChunk(alloc_size);
  result = new_chunk->allocBlock(alloc_size);
  return result;
}

MemChunk * MemoryArena::allocChunk(size_t alloc_size) {
  size_t chunk_size = ALIGN_CEIL(alloc_size, OSMemory::PageSize());
  addr_t chunk_addr = (addr_t)OSMemory::Allocate(chunk_size, kNoAccess);

  MemChunk *chunk = new MemChunk{.addr = chunk_addr, .cursor_addr = chunk_addr, .size = chunk_size};
  chunks_.push_back(chunk);
  return chunk;
}

MemChunk * CodeMemoryArena::allocChunk(size_t alloc_size) {
  MemChunk *chunk = MemoryArena::allocChunk(alloc_size);
  OSMemory::SetPermission((void *)chunk->addr, chunk->size, kReadExecute);
  return chunk;
}

MemChunk * DataMemoryArena::allocChunk(size_t alloc_size) {
  MemChunk *chunk = MemoryArena::allocChunk(alloc_size);
  OSMemory::SetPermission((void *)chunk->addr, chunk->size, kReadWrite);
  return chunk;
}