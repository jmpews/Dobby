#include "globals.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/arch/x64/registers-x64.h"
#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "ExecMemory/ExecutableMemoryArena.h"
#include "PlatformInterface/ExecMemory/CodePatchTool.h"

#include "InstructionRelocation/x86/X86OpcodoDecodeTable.h"

#include "logging/logging.h"

#include "stdcxx/LiteMemOpt.h"

using namespace zz::x64;

AssemblyCode *GenRelocateCodeTo(void *buffer, int *relocate_size, uint64_t from_ip, uint64_t to_ip) {
  uint64_t cur_addr    = (uint64_t)buffer;
  uint64_t cur_src_ip  = from_ip;
  uint64_t cur_dest_ip = to_ip;
  byte opcode1         = *(byte *)cur_addr;

  InstrMnemonic instr = {0};
  TurboAssembler turbo_assembler_(0);
  // Set fixed executable code chunk address
  turbo_assembler_.CommitRealizeAddress((void *)to_ip);
#define _ turbo_assembler_.
#define __ turbo_assembler_.GetCodeBuffer()->
  while ((cur_addr < ((uint64_t)buffer + *relocate_size))) {
    OpcodeDecodeItem *decodeItem = &OpcodeDecodeTable[opcode1];
    decodeItem->DecodeHandler(&instr, (uint64_t)cur_addr);

    // Jcc Relocate OpcodeEncoding=D and rel8
    // Solution:
    // Convert to 32bit AKA rel32
    if (instr.instr.opcode1 >= 0x70 && instr.instr.opcode1 <= 0x7F) {
      int orig_offset = *(byte *)&instr.instr.Immediate;
      int offset      = (int)(cur_src_ip + orig_offset - cur_dest_ip);
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
      byte offset      = cur_src_ip + orig_offset - cur_dest_ip;
      __ Emit8(0xE9);
      __ Emit32(offset);
    } else if (instr.instr.opcode1 == 0xE8 || instr.instr.opcode1 == 0xE9) {
      // JMP/CALL rel32
      dword orig_offset = *(dword *)&instr.instr.Immediate;
      dword offset      = (dword)(cur_src_ip + orig_offset - cur_dest_ip);
      __ Emit8(instr.instr.opcode1);
      __ Emit32(offset);
    } else if (instr.flag & kIPRelativeAddress) {
      // IP-Relative Address
      dword orig_disp = *(dword *)(cur_addr + instr.instr.DisplacementOffset);
      dword disp      = (dword)(cur_src_ip + orig_disp - cur_dest_ip);
#if 0
      byte InstrArray[15];
      LiteMemOpt::copy(InstrArray, cur_ip, instr.len);
      *(dword *)(InstrArray + instr.instr.DisplacementOffset) = disp;
      _ Emit(InstrArray, instr.len);

#else
      __ EmitBuffer((void *)cur_addr, instr.instr.DisplacementOffset);
      __ Emit32(disp);
#endif
    } else {
      // Emit the origin instrution
      __ EmitBuffer((void *)cur_addr, instr.len);
    }

    // go next
    cur_src_ip += instr.len;
    cur_dest_ip += instr.len;
    cur_addr += instr.len;
    opcode1 = *(byte *)cur_addr;

    // clear instr structure
    _memset((void *)&instr, 0, sizeof(InstrMnemonic));
  }
  
  // jmp to the origin rest instructions
  CodeGen codegen(&turbo_assembler_);
  codegen.JmpBranch((addr_t)cur_src_ip);

  // Generate executable code
  CodePatch(turbo_assembler_.GetRealizeAddress(), turbo_assembler_.GetCodeBuffer()->getRawBuffer(),
            turbo_assembler_.GetCodeBuffer()->getSize());
  // Alloc a new AssemblyCode
  AssemblyCode *code = new AssemblyCode;
  code->initWithAddressRange((addr_t)turbo_assembler_.GetRealizeAddress(), turbo_assembler_.GetCodeBuffer()->getSize());
  return code;
}

AssemblyCode *GenRelocateCode(void *buffer, int *relocate_size, addr_t from_pc, addr_t to_pc) {
  int relo_code_chunk_size = 32;
  int chunk_size_step      = 16;
  AssemblyCodeChunk *codeChunk;
  AssemblyCode *code;
  if (to_pc == 0) {
    codeChunk = ExecutableMemoryArena::AllocateCodeChunk(relo_code_chunk_size);
    to_pc     = (uint64_t)codeChunk->address;
  }

  code = GenRelocateCodeTo(buffer, relocate_size, from_pc, to_pc);

  while (code->raw_instruction_size() > codeChunk->size) {
    // free the codeChunk
    ExecutableMemoryArena::Destory(codeChunk);

    relo_code_chunk_size += chunk_size_step;
    codeChunk = ExecutableMemoryArena::AllocateCodeChunk(relo_code_chunk_size);
    to_pc     = (uint64_t)codeChunk->address;
    code      = GenRelocateCodeTo(buffer, relocate_size, from_pc, to_pc);
  }

  return code;
}
