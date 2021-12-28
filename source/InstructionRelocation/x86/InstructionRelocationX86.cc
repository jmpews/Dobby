#include "platform_macro.h"
#if defined(TARGET_ARCH_IA32)

#include "dobby_internal.h"

#include "InstructionRelocation/x86/InstructionRelocationX86.h"
#include "InstructionRelocation/x86/x86_insn_decode/x86_insn_decode.h"

#include "core/arch/x86/registers-x86.h"
#include "core/assembler/assembler-ia32.h"
#include "core/codegen/codegen-ia32.h"

using namespace zz::x86;

int GenRelocateCodeFixed(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated) {
  TurboAssembler turbo_assembler_(0);
  // Set fixed executable code chunk address
  turbo_assembler_.SetRealizedAddress((void *)relocated->addr);
#define _ turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->

  auto curr_orig_ip = (addr32_t)origin->addr;
  auto curr_relo_ip = (addr32_t)relocated->addr;

  uint8_t *buffer_cursor = (uint8_t *)buffer;

  x86_options_t conf = {0};
  conf.mode = 32;

  int predefined_relocate_size = origin->size;

  while ((buffer_cursor < ((uint8_t *)buffer + predefined_relocate_size))) {
    int last_relo_offset = turbo_assembler_.GetCodeBuffer()->GetBufferSize();

    x86_insn_decode_t insn = {0};
    memset(&insn, 0, sizeof(insn));
    // decode x86 insn
    x86_insn_decode(&insn, (uint8_t *)buffer_cursor, &conf);

    if (insn.primary_opcode >= 0x70 && insn.primary_opcode <= 0x7F) { // jc rel8
      DLOG(0, "[x86 relo] jc rel8, %p", buffer_cursor);

      int8_t orig_offset = insn.immediate;
      int new_offset = (int)(curr_orig_ip + orig_offset - curr_relo_ip);
      uint8_t opcode = 0x80 | (insn.primary_opcode & 0x0f);

      __ Emit8(0x0F);
      __ Emit8(opcode);
      __ Emit32(new_offset);
    } else if (insn.primary_opcode == 0xEB) { // jmp rel8
      DLOG(0, "[x86 relo] jmp rel8, %p", buffer_cursor);

      int8_t orig_offset = insn.immediate;
      int8_t new_offset = (int8_t)(curr_orig_ip + orig_offset - curr_relo_ip);

      __ Emit8(0xE9);
      __ Emit32(new_offset);
    } else if (insn.primary_opcode == 0xE8 || insn.primary_opcode == 0xE9) { // call or jmp rel32
      DLOG(0, "[x86 relo] jmp or call rel32, %p", buffer_cursor);

      int32_t orig_offset = insn.immediate;
      int32_t offset = (int32_t)(curr_orig_ip + orig_offset - curr_relo_ip);

      __ EmitBuffer(buffer_cursor, insn.immediate_offset);
      __ Emit32(offset);
    } else if (insn.primary_opcode >= 0xE0 && insn.primary_opcode <= 0xE2) { // LOOPNZ/LOOPZ/LOOP/JECXZ
      // LOOP/LOOPcc
      UNIMPLEMENTED();
    } else if (insn.primary_opcode == 0xE3) {
      // JCXZ JCEXZ JCRXZ
      UNIMPLEMENTED();
    } else {
      // Emit the origin instrution
      __ EmitBuffer(buffer_cursor, insn.length);
    }

    // go next
    curr_orig_ip += insn.length;
    buffer_cursor += insn.length;

#if 0
    {
      // 1 orignal instrution => ? relocated instruction
      int relo_offset = turbo_assembler_.GetCodeBuffer()->GetBufferSize();
      int relo_len    = relo_offset - last_relo_offset;
      curr_relo_ip += relo_len;
    }
#endif
    curr_relo_ip = (addr32_t)relocated->addr + turbo_assembler_.ip_offset();
  }

  // jmp to the origin rest instructions
  CodeGen codegen(&turbo_assembler_);
  addr64_t stub_addr = curr_relo_ip + 6;
  codegen.JmpNear(curr_orig_ip);

  // update origin
  int new_origin_len = curr_orig_ip - (addr_t)origin->addr;
  origin->reset(origin->addr, new_origin_len);

  int relo_len = turbo_assembler_.GetCodeBuffer()->GetBufferSize();
  if (relo_len > relocated->size) {
    DLOG(0, "pre-alloc code chunk not enough");
    return RT_FAILED;
  }

  // Generate executable code
  {
    AssemblyCode *code = NULL;
    code = AssemblyCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
    delete code;
  }

  return RT_SUCCESS;
}

void GenRelocateCodeAndBranch(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated) {
  GenRelocateCodeAndBranchX86Shared(buffer, origin, relocated);
}

#endif
