#pragma once

#include <stdint.h>
#include <sys/types.h>

#if defined(BUILD_DYLD_LINKER)
#include "dyld_linker/external_call.h"
#define DEBUG_LOG DYLD_DEBUG_LOG
#else
#include "logging/logging.h"
#endif

#if !defined(ALIGN_FLOOR)
#define ALIGN_FLOOR(address, range) ((uintptr_t)address & ~((uintptr_t)range - 1))
#define ALIGN_CEIL(address, range) (((uintptr_t)address + (uintptr_t)range - 1) & ~((uintptr_t)range - 1))
#endif

#define MEM_BLOCK_USED_MAGIC (0xdeadbeef + 1)
#define MEM_BLOCK_FREE_MAGIC (0xdeadbeef + 2)

#define macro_assert(x)                                                                                                \
  if (!(x)) {                                                                                                          \
    *(int *)0x41414141 = 0;                                                                                            \
  }

struct simple_linear_allocator_t {
  uint8_t *buffer;
  uint32_t size = 0;
  uint32_t capacity;
  uint32_t builtin_alignment;

  simple_linear_allocator_t() = default;

  explicit simple_linear_allocator_t(uint8_t *buffer, uint32_t capacity, uint32_t alignment = 8) {
    init(buffer, capacity, alignment);
  }

  void init(uint8_t *in_buffer, uint32_t in_capacity, uint32_t in_alignment = 8) {
    buffer = in_buffer;
    capacity = in_capacity;
    builtin_alignment = in_alignment;
    if (builtin_alignment == 0) {
      builtin_alignment = 1;
    }
    size = 0;
  }

  uint8_t *alloc(uint32_t in_size, uint32_t in_alignment = 0) {
    auto alignment = in_alignment ? in_alignment : builtin_alignment;
    uint32_t gap_size = ALIGN_CEIL((uintptr_t)cursor(), alignment) - (uintptr_t)cursor();
    size += gap_size;

    if (size + in_size > capacity) {
      return nullptr;
    }

    auto data = cursor();
    // DEBUG_LOG("alloc: %p - %p", data, in_size);

    size += in_size;
    return data;
  }

  void free(uint8_t *buf) {
    // do nothing
  }

  uint8_t *cursor() {
    return buffer + size;
  }
};

struct linear_allocator_t {
  struct mem_block_t {
    uint32_t magic;
    uint32_t data_size_;
    uint8_t data[0];

    mem_block_t() = default;

    inline uint32_t data_size() {
      return data_size_;
    }

    inline uint32_t block_size() {
      return sizeof(mem_block_t) + data_size_;
    }

    inline void mark_used() {
      magic = MEM_BLOCK_USED_MAGIC;
    }

    inline void mark_freed() {
      magic = MEM_BLOCK_FREE_MAGIC;
    }

    inline bool is_used() {
      return magic == MEM_BLOCK_USED_MAGIC;
    }

    inline bool is_freed() {
      return magic == MEM_BLOCK_FREE_MAGIC;
    }

    mem_block_t *next_block() {
      return (mem_block_t *)(data + data_size_);
    }

    void reset() {
      magic = 0;
      data_size_ = 0;
    }

    void try_split(uint32_t truncated_size) {
      if (magic != MEM_BLOCK_FREE_MAGIC)
        return;

      // do nothing if truncated_size is too small
      if (truncated_size >= data_size())
        return;

      // create next block
      auto next_block_cursor = data + truncated_size;
      auto next_block_size = data_size() - truncated_size;
      auto next_data_size = next_block_size - (uint32_t)sizeof(mem_block_t);
      macro_assert(next_data_size % sizeof(mem_block_t) == 0);
      mem_block_t::create_free_block(next_block_cursor, next_data_size);

      // update current block
      this->data_size_ = truncated_size;
    }

    void try_merge_next() {
      if (magic != MEM_BLOCK_FREE_MAGIC)
        return;

      auto next_blk = next_block();
      if (!next_blk->is_freed())
        return;

      // update current block
      data_size_ = data_size() + next_blk->block_size();

      // reset next block
      next_blk->reset();
    }

    void free() {
      mark_freed();
      try_merge_next();
    }

    static mem_block_t *create(uint32_t magic, uint8_t *cursor, uint32_t in_data_size) {
      auto *block = (mem_block_t *)cursor;
      block->magic = magic;
      block->data_size_ = in_data_size;
      return block;
    }

    static mem_block_t *create_used_block(uint8_t *cursor, uint32_t in_data_size) {
      return create(MEM_BLOCK_USED_MAGIC, cursor, in_data_size);
    }

    static mem_block_t *create_free_block(uint8_t *cursor, uint32_t in_data_size) {
      return create(MEM_BLOCK_FREE_MAGIC, cursor, in_data_size);
    }

    static inline mem_block_t *with_buf(uint8_t *buf) {
      return (mem_block_t *)(buf - sizeof(mem_block_t));
    }
  };

  uint8_t *buffer;
  uint32_t buffer_size;

  bool is_free_blocks_merged;

  linear_allocator_t() = default;

  linear_allocator_t(uint8_t *in_buffer, uint32_t in_buffer_size) {
    init(in_buffer, in_buffer_size);
  }

  void init(uint8_t *in_buffer, uint32_t in_buffer_size) {
    this->buffer = in_buffer;
    this->buffer_size = in_buffer_size;
    this->is_free_blocks_merged = true;

    mem_block_t::create_free_block(buffer, buffer_size - sizeof(mem_block_t));
  }

  void try_merge_free_blocks() {
    for (uint8_t *cursor = buffer; cursor < buffer + buffer_size;) {
      auto *block = (mem_block_t *)cursor;
      block->try_merge_next();
      cursor += block->block_size();
    }
  }

  uint8_t *alloc(uint32_t in_data_size) {
    in_data_size = (uint32_t)ALIGN_CEIL(in_data_size, sizeof(mem_block_t));

    mem_block_t *freed_blk = nullptr;
    for (uint8_t *cursor = buffer; cursor < buffer + buffer_size;) {
      auto *block = (mem_block_t *)cursor;
      if (block->magic == MEM_BLOCK_FREE_MAGIC && block->data_size() >= in_data_size) {
        block->try_split(in_data_size);
        freed_blk = block;
        break;
      }

      cursor += block->block_size();
    }

    if (freed_blk == nullptr) {
      if (!is_free_blocks_merged)
        return nullptr;

      try_merge_free_blocks();
      is_free_blocks_merged = true;

      auto *buf = alloc(in_data_size);
      return buf;
    } else {
      // DEBUG_LOG("alloc: %p", freed_blk->data_size());
      freed_blk->mark_used();
      status();
      return freed_blk->data;
    }
  }

  void free(uint8_t *buf) {
    if (buf == 0)
      return;

    auto *block = mem_block_t::with_buf(buf);
    if (!block->is_used()) {
      DEBUG_LOG("free: invalid magic %p", block->magic);
      return;
    }
    // DEBUG_LOG("free: %p", block->data_size());

    block->free();
    is_free_blocks_merged = false;
    status();
  }

  void status() {
    return;
    uint32_t used_data_size = 0;
    uint32_t used_block_count = 0;
    uint32_t freed_data_size = 0;
    uint32_t freed_block_count = 0;
    for (uint8_t *cursor = buffer; cursor < buffer + buffer_size;) {
      auto *block = (mem_block_t *)cursor;
      if (block->is_used()) {
        used_data_size += block->data_size();
        used_block_count++;
      } else if (block->is_freed()) {
        freed_data_size += block->data_size();
        freed_block_count++;
      }

      cursor += block->block_size();
    }
    DEBUG_LOG("status: used_data_size=%p, used_block_count=%p, freed_data_size=%p, freed_block_count=%p",
              used_data_size, used_block_count, freed_data_size, freed_block_count);
  }
};

extern simple_linear_allocator_t gSimpleLinearAllocator;

extern linear_allocator_t gLinerAllocator;

void linear_allocator_init();
