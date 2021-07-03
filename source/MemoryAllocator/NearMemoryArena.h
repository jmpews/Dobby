
#ifndef MemoryAllocator_NearMemoryArena_h
#define MemoryAllocator_NearMemoryArena_h

#include "MemoryAllocator/MemoryArena.h"

class NearMemoryArena : public DataMemoryArena {
public:
  static NearMemoryArena *SharedInstance() {
    static NearMemoryArena *arena_priv_ = nullptr;
    if (arena_priv_ == nullptr) {
      arena_priv_ = new NearMemoryArena();
    }
    return arena_priv_;
  }

  DataBlock *allocNearDataBlock(addr_t pos, size_t range_size, size_t alloc_size);
};

#endif
