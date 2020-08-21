#include "common/macros/platform_macro.h"
#if defined(TARGET_ARCH_IA32)

#include "./code-buffer-x86.h"

void CodeBuffer::Emit32(int32_t data) {
  ensureCapacity(getSize() + sizeof(int32_t));
  *reinterpret_cast<int32_t *>(getCursor()) = data;
  cursor_ += sizeof(int32_t);
  return;
}

#endif