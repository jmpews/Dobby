#include "platform_detect_macro.h"
#if TARGET_ARCH_IA32

#include "core/assembler/assembler-ia32.h"

using namespace zz::x86;

void Assembler::jmp(Immediate imm) {
  buffer_->Emit<int8_t>(0xE9);
  buffer_->Emit<int32_t>((int)imm.value());
}

addr32_t TurboAssembler::CurrentIP() {
  return pc_offset() + (addr_t)realized_addr_;
}

void PseudoLabel::link_confused_instructions(CodeMemBuffer *buffer) {
  auto _buffer = (CodeBuffer *)buffer;

  for (auto &ref_label_insn : ref_insts) {
    int64_t new_offset = pos() - ref_label_insn.pc_offset;

    if (ref_label_insn.link_type == kDisp32_off_7) {
      // why 7 ?
      // use `call` and `pop` get the runtime ip register
      // but the ip register not the real call next insn
      // it need add two insn length == 7
      int disp32_fix_pos = ref_label_insn.pc_offset - sizeof(int32_t);
      _buffer->FixBindLabel(disp32_fix_pos, new_offset + 7);
    }
  }
}

#endif