#pragma once

#include <stdint.h>

typedef enum { kFunctionInlineHook, kInstructionInstrument } HookEntryType;

class InterceptRouting;

typedef struct {
  uint32_t id;
  HookEntryType type;
  InterceptRouting *routing;

  addr_t patched_addr;
  uint32_t patched_size;

  addr_t relocated_addr;
  uint32_t relocated_size;

  uint8_t origin_insns[256];
  uint32_t origin_insn_size;
} HookEntry;