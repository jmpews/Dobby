#pragma once

#include "common_header.h"

#include "MemoryAllocator/AssemblyCodeBuilder.h"

int GenRelocateCodeFixed(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated);

void GenRelocateCodeAndBranchX86Shared(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated);

int GenRelocateSingleX86Insn(addr_t curr_orig_ip, addr_t curr_relo_ip, uint8_t *buffer_cursor,
                             CodeBufferBase *code_buffer);