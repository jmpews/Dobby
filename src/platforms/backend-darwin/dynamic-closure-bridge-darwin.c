#include "closure_bridge.h"

DynamicClosureBridge *DynamicClosureBridgeCClass(SharedInstance)() {
  return NULL;
}
DynamicClosureTrampoline *DynamicClosureBridgeCClass(AllocateDynamicClosureBridge)(DynamicClosureBridge *self,
                                                                                   void *carry_data, void *forward_code) {
  return NULL;
}
DynamicClosureTrampolineTable *
DynamicClosureBridgeCClass(AllocateDynamicClosureTrampolineTable)(DynamicClosureBridge *self) {
  return NULL;
}
