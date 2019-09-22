#ifndef HOOKZZ_INTERNAL_H_
#define HOOKZZ_INTERNAL_H_

#include "hookzz.h"

#include "PlatformInterface/Common/Platform.h"
#include "macros.h"

#include "logging/logging.h"
#include "logging/check_logging.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

typedef struct _InstructionBackupArray {
  void *address;
  int size;
  char data[64];
} InstructionBackupArray;

typedef struct _HookEntry {
  union {
    void *target_address;
    void *function_address;
    void *instruction_address;
  };

  unsigned int id;

  HookEntryType type;

  void *route;

  // fixed-instructions which we relocated(patched).
  union {
    void *relocated_origin_instructions;
    void *relocated_origin_function;
  };

  // backup origin instructions
  InstructionBackupArray origin_instructions;
} HookEntry;

#endif