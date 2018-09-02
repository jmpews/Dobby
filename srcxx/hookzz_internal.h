#ifndef ZZ_HOOKZZ_INTERNAL_H_
#define ZZ_HOOKZZ_INTERNAL_H_

#include "hookzz.h"

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

  // `pre_call` will be executed before the function.
  // @access all the register
  // @use in `ZzWrap()`
  PRECALL pre_call;

  // `post_call` will be executed after the function done, in other words, it's will be executed before return to the last function frame, such as the `LR` regisrer has been replaced.
  // @access all the register
  // @use in `ZzWrap`
  POSTCALL post_call;

  // `dbi_call` will be execution before the `instruction_address`
  // @access all the register
  // @use in ZzDynamicBinaryInstrumentation
  DBICALL dbi_call;

  // `replace_call` just normal as inlinehook
  void *replace_call;

  // fixed-instructions which we relocated(patched).
  union {
    void *relocated_origin_instructions;
    void *relocated_origin_function;
  };

  // prologue_dispatch_bridge
  void *prologue_dispatch_bridge;

  // epilogue_dispatch_bridge
  void *epilogue_dispatch_bridge;

  // backup origin instructions
  InstructionBackupArray origin_instructions;
} HookEntry;

#endif