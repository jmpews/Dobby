#ifndef ZZ_CLOSURE_BRIDGE_H_
#define ZZ_CLOSURE_BRIDGE_H_

#include <stdint.h>
#include <vector>

#include "Core.h"
#include "hookzz_interal.h"

typedef struct _ClosureBridgeInfo {
  void *user_code;
  void *user_data;
  void *redirect_trampoline;
} ClosureBridgeInfo;

typedef struct _ClosureBridgeTrampolineTable {
  void *entry;
  void *trampoline_page;
  uint16_t used_count;
  uint16_t free_count;
} ClosureBridgeTrampolineTable;

class ClosureBridge {
public:
  std::vector<ClosureBridgeInfo *> bridge_infos;
  std::vector<ClosureBridgeTrampolineTable *> trampoline_tables;

public:
  ClosureBridgeInfo *allocateClosureBridge(void *user_data, void *user_code);
  ClosureBridgeTrampolineTable *allocateClosureBridgeTrampolineTable();
};

typedef struct _DynamicClosureBridgeInfo {
  void *trampolineTo;

  void *user_code;
  void *user_data;
  void *redirect_trampoline;
} DynamicClosureBridgeInfo;

typedef struct _DynamicClosureTrampolineTable {
  void *entry;
  void *trampoline_page;
  void *data_page;
  uint16_t used_count;
  uint16_t free_count;
} DynamicClosureBridgeTrampolineTable;

class DynamicClosureBridge {
public:
  std::vector<DynamicClosureBridgeInfo *> bridge_infos;
  std::vector<DynamicClosureBridgeTrampolineTable *> trampoline_tables;

public:
  DynamicClosureBridgeInfo *allocateDynamicClosureBridge(void *user_data, void *user_code);
  DynamicClosureBridgeTrampolineTable *addDynamicClosurceBridgeTrampolineTable();
};

typedef void (*USER_CODE_CALL)(RegisterContext *reg_ctx, ClosureBridgeInfo *cb_info);
typedef void (*DYNAMIC_USER_CODE_CALL)(RegisterContext *reg_ctx, DynamicClosureBridgeInfo *dcbInfo);

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void closure_bridge_trampoline_template();

void closure_bridge_template();

void dynamic_closure_bridge_template();

void dynamic_closure_trampoline_table_page();

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //HOOKZZ_CLOSUREBRIDGE_H
