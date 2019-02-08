#include "code-buffer-arm64.h"

arm64_inst_t CodeBuffer::LoadInst(int offset) {
  return *reinterpret_cast<int32_t *>(buffer_ + offset);
}

void CodeBuffer::RewriteInst(int offset, arm64_inst_t inst) {
  *reinterpret_cast<arm64_inst_t *>(buffer_ + offset) = inst;
  return;
}

void CodeBuffer::EmitInst(arm64_inst_t inst) {
  ensureCapacity(size_ + sizeof(arm64_inst_t));
  *reinterpret_cast<arm64_inst_t *>(getCursor()) = inst;
  return;
}

void CodeBuffer::Emit64(int64_t data) {
  ensureCapacity(size_ + sizeof(int64_t));
  *reinterpret_cast<int64_t *>(getCursor()) = data;
}
