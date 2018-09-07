#ifndef ZZ_BASE_OBJECTS_CODE_H_
#define ZZ_BASE_OBJECTS_CODE_H_

#include "vm_core/objects/objects.h"
#include "vm_core/platform/platform.h"

namespace zz {

class Code : public Object {

public:
  // realize the buffer address to runtime code, and create a corresponding Code Object
  static Code *FinalizeCode(uintptr_t address, int size);

  // dummy method
  inline uintptr_t raw_instruction_start() {
    return 0;
  };

  // dummy method
  inline int raw_instruction_size() {
    return 0;
  };

  // dummy method
  void Commit(){};

private:
  uint8_t *instructions_;
};

} // namespace zz

#endif