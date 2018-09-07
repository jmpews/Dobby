#ifndef Z_BASE_MEMORY_CHUNK_H_
#define Z_BASE_MEMORY_CHUNK_H_

#include "vm_core/macros.h"
#include "vm_core/globals.h"
#include "vm_core/logging.h"

namespace zz {

class MemoryChunk {
public:
  MemoryChunk() : size_(0), cursor_(NULL), area_start_(NULL), area_end_(NULL);

  MemoryChunk(void *address, size_t size) : size_(size), area_start_(address) {
    cursor_   = area_start_;
    area_end_ = area_start_ + size_;
  }

  MemoryRegion *Allocate(size_t size) {
    if ((cursor_ + size) > area_end_)
      return NULL;
    MemoryRegion *region = new MemoryRegion(cursor_, size);
    cursor += size;
    return region;
  }

private:
  size_t size_;
  byte *cursor_;
  byte *area_start_;
  byte *area_end_;

  // Dummy
  // memory_blocks in the memory_chunk
  std::vector<MemoryRegion *> memory_regions_;

} // namespace zz

#endif
