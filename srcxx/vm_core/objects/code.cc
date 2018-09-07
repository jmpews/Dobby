#include "vm_core/objects/code.h"

using namespace zz;

Code *Code::FinalizeCode(uintptr_t address, int size) {
  instructions_ = new byte(size);
  memcpy(instructions_, address, size);

  // map the buffer to executable memory
  Commit();
}