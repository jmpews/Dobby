#pragma once

#include "MemoryAllocator/MemoryArena.h"

#include "common_header.h"

class NearMemoryArena : public MemoryArena {
public:
  static NearMemoryArena *SharedInstance() {
    static NearMemoryArena *arena_priv_ = nullptr;
    if (arena_priv_ == nullptr) {
      arena_priv_ = new NearMemoryArena();
    }
    return arena_priv_;
  }

  MemBlock *allocNearBlock(size_t alloc_size, addr_t pos, size_t alloc_range, bool executable);

  DataBlock *allocNearDataBlock(size_t alloc_size, addr_t pos, size_t alloc_range) {
    return allocNearBlock(alloc_size, pos, alloc_range, false);
  }

  CodeBlock *allocNearCodeBlock(size_t alloc_size, addr_t pos, size_t alloc_range) {
    return allocNearBlock(alloc_size, pos, alloc_range, true);
  }

  std::vector<MemChunk *> data_chunks_;
  std::vector<MemChunk *> code_chunks_;
};