#include "./code-buffer-arm.h"

#include "CodeBufferBase.h"

arm_inst_t CodeBuffer::LoadARMInst(int offset) {
  return *reinterpret_cast<arm_inst_t *>(buffer_ + offset);
}

thumb1_inst_t CodeBuffer::LoadThumb1Inst(int offset) {
  return *reinterpret_cast<thumb1_inst_t *>(buffer_ + offset);
};

thumb2_inst_t CodeBuffer::LoadThumb2Inst(int offset) {
  return *reinterpret_cast<thumb2_inst_t *>(buffer_ + offset);
};

void CodeBuffer::RewriteARMInst(int offset, arm_inst_t inst) {
  *reinterpret_cast<arm_inst_t *>(buffer_ + offset) = inst;
  return;
}

void CodeBuffer::RewriteThumb1Inst(int offset, thumb1_inst_t inst) {
  *reinterpret_cast<thumb1_inst_t *>(buffer_ + offset) = inst;
  return;
}

void CodeBuffer::RewriteThumb2Inst(int offset, thumb2_inst_t inst) {
  *reinterpret_cast<thumb2_inst_t *>(buffer_ + offset) = inst;
  return;
}

void CodeBuffer::EmitARMInst(arm_inst_t inst) {
  ensureCapacity(getSize() + sizeof(arm_inst_t));
  *reinterpret_cast<arm_inst_t *>(cursor_) = inst;
  cursor_ += sizeof(arm_inst_t);
  return;
}

void CodeBuffer::EmitThumb1Inst(thumb1_inst_t inst) {
  ensureCapacity(getSize() + sizeof(thumb1_inst_t));
  *reinterpret_cast<thumb1_inst_t *>(cursor_) = inst;
  cursor_ += sizeof(thumb1_inst_t);
  return;
}

void CodeBuffer::EmitThumb2Inst(thumb2_inst_t inst) {
  ensureCapacity(getSize() + sizeof(thumb2_inst_t));
  *reinterpret_cast<thumb2_inst_t *>(cursor_) = inst;
  cursor_ += sizeof(thumb2_inst_t);

  return;
}

void CodeBuffer::Emit32(int32_t data) {
  ensureCapacity(getSize() + sizeof(int32_t));
  *reinterpret_cast<int32_t *>(cursor_) = data;
  cursor_ += sizeof(int32_t);
  return;
}