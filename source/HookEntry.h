#pragma once

#include "dobby_internal.h"

typedef enum { kFunctionWrapper, kFunctionInlineHook, kInstructionInstrument } HookEntryType;

class InterceptRouting;
typedef struct {
  uint32_t id;

  HookEntryType type;
  InterceptRouting *routing;

  addr_t patched_insn_addr;
  uint32_t patched_insn_size;

  addr_t relocated_insn_addr;
  uint32_t relocated_insn_size;

  uint8_t origin_insns[256];
  uint32_t origin_insn_size;
} HookEntry;