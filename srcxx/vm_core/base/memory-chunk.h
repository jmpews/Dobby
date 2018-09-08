#ifndef Z_BASE_MEMORY_CHUNK_H_
#define Z_BASE_MEMORY_CHUNK_H_

#include "vm_core/macros.h"
#include "vm_core/globals.h"
#include "vm_core/logging.h"
#include "vm_core/base/memory-region.h"

namespace zz {

class MemoryChunk {
public:
  MemoryChunk() : size_(0), cursor_(0), area_start_(0), area_end_(0) {
  }

  MemoryChunk(void *address, size_t size) : size_(size), area_start_((uintptr_t)address) {
    cursor_   = area_start_;
    area_end_ = area_start_ + size_;
  }

  MemoryRegion *Allocate(size_t size) {
    if ((cursor_ + size) > area_end_)
      return NULL;
    MemoryRegion *region = new MemoryRegion((void *)cursor_, (uword)size);
    cursor_ += size;
    return region;
  }

private:
  size_t size_;
  uintptr_t cursor_;
  uintptr_t area_start_;
  uintptr_t area_end_;

  // Dummy
  // memory_blocks in the memory_chunk
  std::vector<MemoryRegion *> memory_regions_;
};

} // namespace zz

#endif
