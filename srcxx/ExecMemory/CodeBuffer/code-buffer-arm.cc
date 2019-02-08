#include "CodeBufferBase.h"

arm_inst_t CodeBuffer::LoadARMInst(int offset) { return *static_cast<int32_t *>(buffer_ + offset); }

thumb_inst_t CodeBuffer::LoadThumbInst(int offset) { return *static_cast<int16_t *>(buffer_ + offset); };

void CodeBuffer::RewriteARMInst(int offset, arm_inst_t inst) {
  *reinterpret_cast<arm_inst_t *>(buffer_ + offset) = inst;
  return;
}

void CodeBuffer::RewriteThumbInst(int offset, thumb_inst_t inst) {
  *reinterpret_cast<thumb_inst_t *>(buffer_ + offset) = inst;
  return;
}

void CodeBuffer::EmitARMInst(int offset, arm_inst_t inst) {
  ensureCapacity(length_ + sizeof(arm_inst_t));
  *static_cast<arm_inst_t *>(getCursor()) = inst;
  return;
}

void CodeBuffer::EmitThumbInst(int offset, thumb_inst_t inst) {
  ensureCapacity(length_ + sizeof(thumb_inst_t));
  *static_cast<thumb_inst_t *>(getCursor()) = inst;
  return;
}

void CodeBuffer::Emit32(int32_t data) {
  ensureCapacity(length_ + sizeof(inst32_t));
  *static_cast<int32_t *>(getCursor()) = data;
  return;
}