#pragma once

#include "MemoryAllocator.h"

#include "core/assembler/assembler.h"

using namespace zz;

struct AssemblerCodeBuilder {
  static MemBlock FinalizeFromTurboAssembler(AssemblerBase *assembler) {
    auto code_buffer = assembler->code_buffer();
    auto fixed_addr = (addr_t)assembler->fixed_addr;

#if defined(TEST_WITH_UNICORN)
    // impl: unicorn emulator map memory
    fixed_addr = 0;
#endif

    if (!fixed_addr) {
      size_t buffer_size = 0;
      buffer_size = code_buffer->size();

#if TARGET_ARCH_ARM
      // extra bytes for align needed
      buffer_size += 4;
#endif

      auto block = gMemoryAllocator.allocExecBlock(buffer_size);
      if (block.addr() == 0)
        return MemBlock{};

      fixed_addr = block.addr();
      assembler->set_fixed_addr(fixed_addr);
    }

    DobbyCodePatch((void *)fixed_addr, code_buffer->data(), code_buffer->size());

    return MemBlock(fixed_addr, code_buffer->size());
  }
};
