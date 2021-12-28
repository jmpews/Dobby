#include "platform_macro.h"
#if defined(TARGET_ARCH_IA32) || defined(TARGET_ARCH_X64)

#include "dobby_internal.h"

#include "InstructionRelocation/x86/InstructionRelocationX86.h"
#include "InstructionRelocation/x86/x86_insn_decode/x86_insn_decode.h"

using namespace zz::x86;

int GenRelocateSingleX86Insn(addr_t curr_orig_ip, addr_t curr_relo_ip, uint8_t *buffer_cursor,
                             CodeBufferBase *code_buffer) {
#define __ code_buffer->

  int relocated_insn_len = -1;

  x86_options_t conf = {0};
  conf.mode = 32;

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
    relocated_insn_len = -1;
  }
  return relocated_insn_len;
}

void GenRelocateCodeAndBranchX86Shared(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated) {
  int expected_relocated_mem_size = 32;

x86_try_again:
  if (!relocated->addr) {
    auto relocated_mem = MemoryAllocator::SharedAllocator()->allocateExecMemory(expected_relocated_mem_size);
    if (relocated_mem == nullptr) {
      return;
    }
    relocated->reset((addr_t)relocated_mem, expected_relocated_mem_size);
  }

  int ret = GenRelocateCodeFixed(buffer, origin, relocated);
  if (ret != RT_SUCCESS) {
    // FIXME: destory

    const int step_size = 16;
    expected_relocated_mem_size += step_size;
    relocated->reset(0, 0);

    goto x86_try_again;
  }
}

#endif
