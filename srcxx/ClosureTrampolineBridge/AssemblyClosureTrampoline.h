#ifndef ZZ_ASSEMBLY_CLOSURE_TRAMPOLINE_H_
#define ZZ_ASSEMBLY_CLOSURE_TRAMPOLINE_H_

#include "hookzz_internal.h"

#include "stdcxx/LiteMutableArray.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct _ClosureTrampolineEntry {
  void *carry_handler;
  void *carry_data;
  void *address;
  uintptr_t size;
} ClosureTrampolineEntry;

typedef void (*USER_CODE_CALL)(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry);

void closure_trampoline_template();

void closure_bridge_template();

void *get_closure_bridge();

#ifdef __cplusplus
}
#endif //__cplusplus

class ClosureTrampoline {
private:
  static LiteMutableArray *trampolines_;

public:
  static ClosureTrampolineEntry *CreateClosureTrampoline(void *carry_data, void *carry_handler);
};

#endif
