#ifndef ZZ_BASE_OBJECTS_CODE_H_
#define ZZ_BASE_OBJECTS_CODE_H_

#include "vm_core/globals.h"
#include "vm_core/objects/objects.h"
#include "vm_core/platform/platform.h"

namespace zz {

class Code : public Object {

public:
  Code(void *address, size_t size) : instructions_((uint8_t *)address), instruction_size_(size) {
  }
  // realize the buffer address to runtime code, and create a corresponding Code Object
  static Code *FinalizeCode(uintptr_t address, int size);

  // dummy method
  inline uintptr_t raw_instruction_start() {
    return (uintptr_t)instructions_;
  };

  // dummy method
  inline int raw_instruction_size() {
    return instruction_size_;
  };

  // dummy method
  // void Commit();

private:
  uint8_t *instructions_;
  uword instruction_size_;
};

} // namespace zz

#endif
