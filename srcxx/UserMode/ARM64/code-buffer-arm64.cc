#include "code-buffer-arm64.h"

arm64_inst_t CodeBuffer::LoadInst(int offset) { return *static_cast<int32_t *>(buffer_ + offset); }

void CodeBuffer::RewriteInst(int offset, arm64_inst_t inst) {
  *reinterpret_cast<arm64_inst_t *>(buffer_ + offset) = inst;
  return;
}

void CodeBuffer::EmitInst(int offset, arm64_inst_t inst) {
  ensureCapacity(length_ + sizeof(arm64_inst_t inst));
  *static_cast<thumb_inst_t *>(getCursor()) = inst;
  return;
}

void CodeBuffer::Emit64(int64_t data) {
  ensureCapacity(length_ + sizeof(int64_t));
  *static_cast<int64_t *>(getCursor()) = data;
}
