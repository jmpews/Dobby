#pragma once

#include "MemoryAllocator/CodeMemBuffer.h"

enum trampoline_type_t {
  TRAMPOLINE_UNKNOWN = 0,
  TRAMPOLINE_ARM64_B_XXX,
  TRAMPOLINE_ARM64_B_XXX_AND_FORWARD_TRAMP,
  TRAMPOLINE_ARM64_ADRP_ADD_BR,
  TRAMPOLINE_ARM64_LDR_BR,


  CLOSURE_TRAMPOLINE_ARM64,
  FORWARD_TRAMPOLINE_ARM64,

  TRAMPOLINE_X64_JMP,
  CLOSEURE_TRAMPOLINE_X64,
};

struct Trampoline {
  int type;
  CodeMemBlock buffer;

  Trampoline *forward_trampoline;

  Trampoline() : type(0), buffer() {
  }

  Trampoline(int type, CodeMemBlock buffer) : type(type), buffer(buffer) {
  }

  Trampoline(int type, CodeMemBlock buffer, Trampoline *forward)
      : type(type), buffer(buffer), forward_trampoline(forward) {
  }

  addr_t addr() {
    return buffer.addr();
  }

  addr_t size() {
    return buffer.size;
  }

  addr_t forward_addr() {
    return forward_trampoline->addr();
  }

  addr_t forward_size() {
    return forward_trampoline->size();
  }
};