#ifndef closure_bridge_h
#define closure_bridge_h

#include "core.h"
#include "hookzz.h"
#include "std_kit/std_list.h"

#include <stdint.h>

#define PRIVATE

// closure bridge
typedef struct _ClosureTrampoline {
  void *forward_code;
  void *carry_data;
  void *address;
} ClosureTrampolineEntry;

typedef struct _ClosureTrampolineTable {
  void *entry;
  void *trampoline_page;
  uint16_t used_count;
  uint16_t free_count;
} ClosureTrampolineTable;

typedef struct _ClosureBridge {
  list_t *trampolines;
  list_t *trampoline_tables;
} ClosureBridge;

#define ClosureBridgeCClass(member) cxxclass(ClosureBridge, member)

ClosureBridge *ClosureBridgeCClass(SharedInstance)();
ClosureTrampolineEntry *ClosureBridgeCClass(CreateClosureTrampoline)(ClosureBridge *self, void *carry_data,
                                                                     void *forward_code);

ClosureTrampolineTable *ClosureBridgeCClass(AllocateClosureTrampolineTable)(ClosureBridge *self);
ARCH_API void ClosureBridgeCClass(InitializeTablePage)(ClosureTrampolineTable *table, void *page_address);
ARCH_API void ClosureBridgeCClass(InitializeClosureTrampoline)(ClosureTrampolineTable *table,
                                                               ClosureTrampolineEntry *entry, void *carry_data,
                                                               void *forward_code);
typedef void (*USER_CODE_CALL)(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry);

#if DYNAMIC_CLOSURE_BRIDGE
// dynamic closure bridge
typedef struct _DynamicClosureTrampoline {
  void *trampolineTo PRIVATE;

  void *forward_code;
  void *carry_data;
  void *address;
} DynamicClosureTrampoline;

typedef struct _DynamicClosureTrampolineTable {
  void *entry;
  void *trampoline_page;
  void *data_page;
  uint16_t used_count;
  uint16_t free_count;
} DynamicClosureTrampolineTable;

typedef struct _DynamicClosureBridge {
  list_t *dynamic_trampolines;
  list_t *dynamic_trampoline_tables;
} DynamicClosureBridge;

#define DynamicClosureBridgeCClass(member) cclass(DynamicClosureBridge, member)

DynamicClosureBridge *DynamicClosureBridgeCClass(SharedInstance)();
DynamicClosureTrampoline *DynamicClosureBridgeCClass(AllocateDynamicClosureBridge)(DynamicClosureBridge *self,
                                                                                   void *carry_data,
                                                                                   void *forward_code);
DynamicClosureTrampolineTable *
    DynamicClosureBridgeCClass(AllocateDynamicClosureTrampolineTable)(DynamicClosureBridge *self);

typedef void (*DYNAMIC_USER_CODE_CALL)(RegisterContext *reg_ctx, DynamicClosureTrampoline *dcb_info);
#endif

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void closure_bridge_trampoline_template();

void closure_bridge_template();

#if DYNAMIC_CLOSURE_BRIDGE
void dynamic_closure_bridge_template();

void dynamic_closure_trampoline_table_page();
#endif

#ifdef __cplusplus
}
#endif //__cplusplus

#endif