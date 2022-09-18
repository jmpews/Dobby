#include "platform_macro.h"

#if defined(TARGET_ARCH_IA32) || defined(TARGET_ARCH_X64)

#include "dobby_internal.h"

#include "InstructionRelocation/x86/InstructionRelocationX86.h"
#include "InstructionRelocation/x86/x86_insn_decode/x86_insn_decode.h"

using namespace zz::x86;

int GenRelocateSingleX86Insn(addr_t curr_orig_ip, addr_t curr_relo_ip, uint8_t *buffer_cursor,
                             CodeBufferBase *code_buffer, x86_insn_decode_t &insn, int8_t mode) {
#define __ code_buffer->

  int relocated_insn_len = -1;

  x86_options_t conf = {0};
  conf.mode = mode;

  // decode x86 insn
  x86_insn_decode(&insn, (uint8_t *)buffer_cursor, &conf);

  // x86 ip register == next instruction
  curr_orig_ip = curr_orig_ip + insn.length;

  int last_relo_offset = code_buffer->GetBufferSize();
  if (insn.primary_opcode >= 0x70 && insn.primary_opcode <= 0x7F) { // jc rel8
    DLOG(0, "[x86 relo] %p: jc rel8", buffer_cursor);

    curr_relo_ip = curr_relo_ip + 6;
    int8_t orig_offset = insn.immediate;
    int32_t new_offset = (int32_t)(curr_orig_ip + orig_offset - curr_relo_ip);

    uint8_t opcode = 0x80 | (insn.primary_opcode & 0x0f);
    __ Emit8(0x0F);
    __ Emit8(opcode);
    __ Emit32(new_offset);
  } else if (mode == 64 && (insn.flags & X86_INSN_DECODE_FLAG_IP_RELATIVE) &&
             (insn.operands[1].mem.base == RIP)) { // RIP
    DLOG(0, "[x86 relo] %p: rip", buffer_cursor);

    curr_relo_ip = curr_relo_ip + 7;
    int32_t orig_disp = insn.operands[1].mem.disp;
    int32_t new_disp = (int32_t)(curr_orig_ip + orig_disp - curr_relo_ip);

    __ EmitBuffer(buffer_cursor, insn.displacement_offset);
    __ Emit32(new_disp);
    if (insn.immediate_offset) {
      __ EmitBuffer((buffer_cursor + insn.immediate_offset), insn.length - insn.immediate_offset);
    }
  } else if (insn.primary_opcode == 0xEB) { // jmp rel8
    DLOG(0, "[x86 relo] %p: jmp rel8", buffer_cursor);

    curr_relo_ip = curr_relo_ip + 5;
    int8_t orig_offset = insn.immediate;
    int32_t new_offset = (int32_t)(curr_orig_ip + orig_offset - curr_relo_ip);

    __ Emit8(0xE9);
    __ Emit32(new_offset);
  } else if (insn.primary_opcode == 0xE8 || insn.primary_opcode == 0xE9) { // call or jmp rel32
    DLOG(0, "[x86 relo] %p:jmp or call rel32", buffer_cursor);

    curr_relo_ip = curr_relo_ip + 5;
    int32_t orig_offset = insn.immediate;
    int32_t new_offset = (int32_t)(curr_orig_ip + orig_offset - curr_relo_ip);

    assert(insn.immediate_offset == 1);
    __ EmitBuffer(buffer_cursor, insn.immediate_offset);
    __ Emit32(new_offset);
  } else if (insn.primary_opcode >= 0xE0 && insn.primary_opcode <= 0xE2) { // LOOPNZ/LOOPZ/LOOP/JECXZ
    // LOOP/LOOPcc
    UNIMPLEMENTED();
  } else if (insn.primary_opcode == 0xE3) {
    // JCXZ JCEXZ JCRXZ
    UNIMPLEMENTED();
  } else {
    __ EmitBuffer(buffer_cursor, insn.length);
  }

  // insn -> relocated insn
  {
    int relo_offset = code_buffer->GetBufferSize();
    int relo_len = relo_offset - last_relo_offset;
    DLOG(0, "insn -> relocated insn: %d -> %d", insn.length, relo_len);
  }
  return relocated_insn_len;
}

void GenRelocateCodeX86Shared(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch) {
  int expected_relocated_mem_size = 32;

x86_try_again:
  if (!relocated->addr) {
    auto relocated_mem = MemoryAllocator::SharedAllocator()->allocateExecMemory(expected_relocated_mem_size);
    if (relocated_mem == nullptr) {
      return;
    }
    relocated->reset((addr_t)relocated_mem, expected_relocated_mem_size);
  }

  int ret = GenRelocateCodeFixed(buffer, origin, relocated, branch);
  if (ret != RT_SUCCESS) {
    const int step_size = 16;
    expected_relocated_mem_size += step_size;
    relocated->reset(0, 0);

    goto x86_try_again;
  }
}

#endif
