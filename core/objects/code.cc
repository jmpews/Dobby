#include "vm_core/objects/code.h"

namespace zz {

Code *Code::FinalizeFromAddress(uintptr_t address, int size) {
  Code *code = new Code((void *)address, size);
  return code;
}

} // namespace zz
