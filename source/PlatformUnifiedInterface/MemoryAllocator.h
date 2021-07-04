#pragma once

#include "common_header.h"

// ----- range + zone -----

struct MemRange {
  void *begin;
  size_t size;
};

struct MemZone {
  void addRange(MemRange);

private:
  std::vector<MemRange> ranges_;
};

inline void MemZone::addRange(MemRange range) {
  ranges_.push_back(range);
}

// ----- block + chunk -----

struct MemBlock {
  addr_t addr;
  size_t size;
};

struct MemChunk {
  addr_t addr;
  addr_t cursor_addr;
  size_t size;

  MemBlock *allocBlock(size_t alloc_size) {
    if ((addr + size )  - cursor_addr  < alloc_size)
      return nullptr;

    auto *block = new MemBlock{.addr = cursor_addr, .size = alloc_size};
    blocks_.push_back(block);

    cursor_addr += alloc_size;

    return block;
  }

  std::vector<MemBlock *> blocks_;
};

// ----- arena -----

class MemoryArena {
public:
  MemBlock *allocBlock(size_t alloc_size);

protected:
  virtual MemChunk *allocChunk(size_t alloc_size);

protected:
  std::vector<MemChunk *> chunks_;
};

using CodeBlock = MemBlock;
class CodeMemoryArena : public MemoryArena {
public:
  CodeBlock *allocCodeBlock(size_t alloc_size) {
    return allocBlock(alloc_size);
  }

  static CodeMemoryArena *SharedInstance() {
    static CodeMemoryArena *arena_priv_ = nullptr;
    if (arena_priv_ == nullptr) {
      arena_priv_ = new CodeMemoryArena();
    }
    return arena_priv_;
  }

private:
  MemChunk *allocChunk(size_t alloc_size) override;
};

using DataBlock = MemBlock;
class DataMemoryArena : public MemoryArena {
public:
  DataBlock *allocDataBlock(size_t alloc_size) {
    return allocBlock(alloc_size);
  }

  static DataMemoryArena *SharedInstance() {
    static DataMemoryArena *arena_priv_ = nullptr;
    if (arena_priv_ == nullptr) {
      arena_priv_ = new DataMemoryArena();
    }
    return arena_priv_;
  }

private:
  MemChunk *allocChunk(size_t alloc_size) override;
};