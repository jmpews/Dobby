#include "globals.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/arch/x64/registers-x64.h"
#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "ExecMemory/ExecutableMemoryArena.h"
#include "ExecMemory/CodePatchTool.h"

#include "InstructionRelocation/x86/X86OpcodoDecodeTable.h"

#include "logging/logging.h"

#include "stdcxx/LiteMemOpt.h"

namespace zz {
namespace x64 {

AssemblyCode *GenRelocateCodeTo(addr_t src_address, int *relocate_size, AssemblyCodeChunk *codeChunk) {
  addr_t src_ip = src_address;
  addr_t cur_ip = src_ip;
  byte opcode1  = *(byte *)src_ip;

  InstrMnemonic instr = {0};
  TurboAssembler turbo_assembler_;
  // Set fixed executable code chunk address
  turbo_assembler_.CommitRealizeAddress(codeChunk->address);
#define _ turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->
  while ((cur_ip < (src_ip + *relocate_size))) {
    OpcodeDecodeItem *decodeItem = &OpcodeDecodeTable[opcode1];
    decodeItem->DecodeHandler(&instr, (addr_t)cur_ip);

    // Jcc Relocate OpcodeEncoding=D and rel8
    // Solution:
    // Convert to 32bit AKA rel32
    if (instr.instr.opcode1 >= 0x70 && instr.instr.opcode1 <= 0x7F) {
      int orig_offset = *(byte *)&instr.instr.Immediate;
      int offset      = (int)(cur_ip + orig_offset - turbo_assembler_.CurrentIP());
      __ Emit8(0x0F);
      __ Emit8(opcode1);
      __ Emit32(offset);
    } else if (instr.instr.opcode1 >= 0xE0 && instr.instr.opcode1 <= 0xE2) {
      // LOOP/LOOPcc
      UNIMPLEMENTED();
    } else if (instr.instr.opcode1 >= 0xE3) {
      // JCXZ JCEXZ JCRXZ
      UNIMPLEMENTED();
    } else if (instr.instr.opcode1 >= 0xEB) {
      // JMP rel8
      byte orig_offset = *(byte *)&instr.instr.Immediate;
      byte offset      = cur_ip + orig_offset - turbo_assembler_.CurrentIP();
      __ Emit8(0xE9);
      __ Emit32(offset);
    } else if (instr.instr.opcode1 == 0xE8 || instr.instr.opcode1 == 0xE9) {
      // JMP/CALL rel32
      dword orig_offset = *(dword *)&instr.instr.Immediate;
      dword offset      = (dword)(cur_ip + orig_offset - turbo_assembler_.CurrentIP());
      __ Emit8(instr.instr.opcode1);
      __ Emit32(offset);
    } else if (instr.flag & kIPRelativeAddress) {
      // IP-Relative Address
      dword orig_disp = *(dword *)(cur_ip + instr.instr.DisplacementOffset);
      dword disp      = (dword)(cur_ip + orig_disp - turbo_assembler_.CurrentIP());
#if 0
      byte InstrArray[15];
      LiteMemOpt::copy(InstrArray, cur_ip, instr.len);
      *(dword *)(InstrArray + instr.instr.DisplacementOffset) = disp;
      _ Emit(InstrArray, instr.len);

#else
      __ EmitBuffer((void *)cur_ip, instr.instr.DisplacementOffset);
      __ Emit32(disp);
#endif
    } else {
      // Emit the origin instrution
      __ EmitBuffer((void *)cur_ip, instr.len);
    }

    // go next
    cur_ip += instr.len;
    opcode1 = *(byte *)cur_ip;

    // clear instr structure
    memset((void *)&instr, 0, sizeof(InstrMnemonic));
  }

  // Generate executable code
  CodePatchTool::PatchCodeBuffer(turbo_assembler_.GetRealizeAddress(),
                                 reinterpret_cast<CodeBufferBase *>(turbo_assembler_.GetCodeBuffer()));
  // Alloc a new AssemblyCode
  AssemblyCode *code = new AssemblyCode;
  code->initWithAddressRange(turbo_assembler_.GetRealizeAddress(), turbo_assembler_.GetCodeBuffer()->getSize());
  return code;
}

AssemblyCode *GenRelocateCode(uint64_t src_address, int *relocate_size) {
  int relo_code_chunk_size = 32;
  int chunk_size_step      = 16;
  AssemblyCodeChunk *codeChunk;
  AssemblyCode *code;

  codeChunk = ExecutableMemoryArena::AllocateCodeChunk(relo_code_chunk_size);

  code = GenRelocateCodeTo((addr_t)src_address, relocate_size, codeChunk);

  while (!code) {
    // free the codeChunk
    ExecutableMemoryArena::Destory(codeChunk);

    relo_code_chunk_size += chunk_size_step;
    codeChunk = ExecutableMemoryArena::AllocateCodeChunk(relo_code_chunk_size);
    code      = GenRelocateCodeTo((addr_t)src_address, relocate_size, codeChunk);
  }

  return code;
}

} // namespace x64
} // namespace zz
