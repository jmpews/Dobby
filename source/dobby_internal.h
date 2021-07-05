#ifndef DOBBY_INTERNAL_H
#define DOBBY_INTERNAL_H

#include "common_header.h"

#include "dobby.h"

#include "logging/logging.h"
#include "logging/check_logging.h"

#include "external/misc-helper/misc-helper/format_printer.h"

#include "UnifiedInterface/platform.h"

#include "PlatformUnifiedInterface/MemoryAllocator.h"
#include "PlatformUnifiedInterface/ExecMemory/CodePatchTool.h"
#include "PlatformUnifiedInterface/ExecMemory/ClearCacheTool.h"

#include "MemoryAllocator/MemoryArena.h"
#include "MemoryAllocator/AssemblyCodeBuilder.h"

typedef struct {
  AssemblyCode *origin_code;
  uint8_t origin_code_buffer[64];
} AssemblyCodeBuffer;

typedef enum { kFunctionWrapper, kFunctionInlineHook, kDynamicBinaryInstrument } HookEntryType;

typedef struct {
  int id;
  int type;

  union {
    void *target_address;
    void *function_address;
    void *instruction_address;
  };

  void *route;

  // fixed-instructions which we relocated(patched)
  union {
    void *relocated_origin_instructions;
    void *relocated_origin_function;
  };

  AssemblyCodeBuffer origin_code_;
} HookEntry;

#endif
