#include "platform_macro.h"
#if TARGET_ARCH_ARM

#include "core/assembler/assembler-arm.h"

void AssemblerPseudoLabel::link_confused_instructions(CodeBufferBase *buffer) {
  CodeBuffer *_buffer = (CodeBuffer *)buffer;

  for (auto &ref_label_inst : ref_label_insts_) {
    int64_t new_offset = relocated_pos() - ref_label_inst.offset_;

    arm_inst_t inst = _buffer->LoadARMInst(ref_label_inst.offset_);
    arm_inst_t new_inst = 0;

    switch (ref_label_inst.type_) {
    case kLdrLiteral: {
      new_inst = inst & 0xfffff000;
      uint32_t imm12 = new_offset - ARM_PC_OFFSET;
      new_inst = new_inst | imm12;
    } break;

      _buffer->RewriteARMInst(ref_label_inst.offset_, new_inst);
    }
  }
}

namespace zz {
namespace arm {

void Assembler::EmitARMInst(arm_inst_t instr) {
  buffer_->EmitARMInst(instr);
}

void Assembler::EmitAddress(uint32_t value) {
  buffer_->Emit32(value);
}

} // namespace arm
} // namespace zz

#endif