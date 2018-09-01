#ifndef ZZ_CLOSURE_BRIDGE_H_
#define ZZ_CLOSURE_BRIDGE_H_

#include <iostream>
#include <stdint.h>
#include <vector>

#include "srcxx/hookzz_internal.h"

#include "vm_core/objects/code.h"

typedef void (*USER_CODE_CALL)(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry);

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct _ClosureTrampolineEntry {
  void *forward_code;
  void *carry_data;
  void *address;
  uintptr_t size;
} ClosureTrampolineEntry;

void closure_trampoline_template();

void closure_bridge_template();

#ifdef __cplusplus
}
#endif //__cplusplus

class ClosureTrampoline : Code {
private:
  std::vector<ClosureTrampolineEntry *> trampolines_;

public:
  ClosureTrampolineEntry *CreateClosureTrampoline(void *carry_data, void *forward_code);
};

#endif
