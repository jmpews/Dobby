#ifndef ZZ_ASSEMBLY_CLOSURE_TRAMPOLINE_H_
#define ZZ_ASSEMBLY_CLOSURE_TRAMPOLINE_H_

#include <iostream>
#include <stdint.h>
#include <vector>

#include "srcxx/hookzz_internal.h"

#include "vm_core/objects/code.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct _ClosureTrampolineEntry {
  void *forward_code;
  void *carry_data;
  void *address;
  uintptr_t size;
} ClosureTrampolineEntry;

typedef void (*USER_CODE_CALL)(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry);

void closure_trampoline_template();

void closure_bridge_template();

#ifdef __cplusplus
}
#endif //__cplusplus

class ClosureTrampoline {
private:
  static std::vector<ClosureTrampolineEntry *> trampolines_;

public:
  static ClosureTrampolineEntry *CreateClosureTrampoline(void *carry_data, void *forward_code);
};

#endif
