#ifndef ZZ_CLOSURE_BRIDGE_H_
#define ZZ_CLOSURE_BRIDGE_H_

#include <stdint.h>
#include <vector>

#include "srcxx/hookzz_internal.h"

typedef struct _ClosureTrampolineEntry {
  void *forward_code;
  void *carry_data;
  void *address;
  uintptr_t size;
} ClosureTrampolineEntry;

class ClosureTrampoline {
private:
  std::vector<ClosureTrampolineEntry *> trampolines_;

public:
  ClosureTrampolineEntry *CreateClosureTrampoline(void *carry_data, void *forward_code);
};

typedef void (*USER_CODE_CALL)(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry);

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void closure_bridge_trampoline_template();

void closure_bridge_template();

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
