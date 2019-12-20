#include "globals.h"

#include "InstructionRelocation/arm64/ARM64InstructionRelocation.h"

#include "core/arch/arm64/registers-arm64.h"
#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

#include "ExecMemory/ExecutableMemoryArena.h"

#include "PlatformInterface/ExecMemory/CodePatchTool.h"

using namespace zz::arm64;

// Compare and branch.
enum CompareBranchOp {
  CompareBranchFixed     = 0x34000000,
  CompareBranchFixedMask = 0x7E000000,
  CompareBranchMask      = 0xFF000000,
};

// Conditional branch.
enum ConditionalBranchOp {
  ConditionalBranchFixed     = 0x54000000,
  ConditionalBranchFixedMask = 0xFE000000,
  ConditionalBranchMask      = 0xFF000010,
};

typedef struct _PseudoLabelData {
  PseudoLabel label;
  uint64_t address;

public:
  _PseudoLabelData(uint64_t address) {
    address = address;
  }
} PseudoLabelData;

#include "MachOManipulator/MachOManipulator.h"
extern MachoManipulator *mm;
extern void *TranslateVa2Rt(void *va, void *machoFileRuntimeMemory);

AssemblyCode *GenRelocateCode(void *buffer, int *relocate_size, addr_t from_pc, addr_t to_pc) {
  from_pc = (addr_t)buffer;
  buffer = TranslateVa2Rt(buffer, mm->mmapFileData);

  bool flag = false; // 是否不应该被hook，即超出跳转范围等
  
  // prologue
  int relo_code_chunk_size = 32;
  int chunk_size_step      = 16;
  AssemblyCodeChunk *codeChunk;
  AssemblyCode *code;
  if (to_pc == 0) {
    codeChunk = ExecutableMemoryArena::AllocateCodeChunk(relo_code_chunk_size);
    to_pc     = (uint64_t)codeChunk->address;
  }

TryRelocateWithNewCodeChunkAgain:
  uint64_t cur_addr    = (uint64_t)buffer;
  uint64_t cur_src_pc  = from_pc;
  uint64_t cur_dest_pc = to_pc;
  uint32_t inst        = *(uint32_t *)cur_addr;

  // std::vector<PseudoLabelData> labels;
  LiteMutableArray *labels = new LiteMutableArray;

  TurboAssembler turbo_assembler_(0);
  // set fixed executable code chunk address
  turbo_assembler_.CommitRealizeAddress((void *)to_pc);
#define _ turbo_assembler_.
  while (cur_addr < ((uint64_t)buffer + *relocate_size)) {
    int off = turbo_assembler_.GetCodeBuffer()->getSize();

    if ((inst & LoadRegLiteralFixedMask) == LoadRegLiteralFixed) {
      int rt                  = bits(inst, 0, 4);
      int32_t imm19           = bits(inst, 5, 23);
      uint64_t target_address = (imm19 << 2) + cur_src_pc;

      //ldr原本只能PC偏移1MB，这里改成了adrp可偏移4GB，所以应该合理
      if((cur_dest_pc - target_address) >= (1UL << 30)){
        flag = true;
        break;
      }
      
      _ AdrpAddMov(X(rt), cur_dest_pc, target_address);
      _ ldr(X(rt), 0);
    } else if ((inst & CompareBranchFixedMask) == CompareBranchFixed) {
      int32_t rt;
      int32_t imm19;
      imm19 = bits(inst, 5, 23);

      int offset                   = (imm19 << 2) + (cur_dest_pc - cur_src_pc);
      imm19                        = offset >> 2;
      
      if(imm19 >= (1L << 18)){//cbz只能跳转偏移1MB
        flag = true;
        break;
      }
      
      int32_t compare_branch_instr = (inst & 0xff00001f) | LFT(imm19, 19, 5);

      _ Emit(compare_branch_instr);
    } else if ((inst & UnconditionalBranchFixedMask) == UnconditionalBranchFixed) {
      int32_t imm26;
      imm26 = bits(inst, 0, 25);

      int32_t offset                     = (imm26 << 2) + (cur_dest_pc - cur_src_pc);
      imm26                              = offset >> 2;
      
      //b指令可以偏移跳转128MB
      if(imm26 >= (1L << 25)){
        flag = true;
        break;
      }
      
      int32_t unconditional_branch_instr = (inst & 0xfc000000) | LFT(imm26, 26, 0);

      _ Emit(unconditional_branch_instr);
    } else if ((inst & ConditionalBranchFixedMask) == ConditionalBranchFixed) {
      int32_t imm19;
      imm19 = bits(inst, 5, 23);

      int offset           = (imm19 << 2) + (cur_dest_pc - cur_src_pc);
      imm19                = offset >> 2;
      
      if(imm19 >= (1L << 18)){//b.cond跳转偏移1MB
        flag = true;
        break;
      }
      
      int32_t b_cond_instr = (inst & 0xff00001f) | LFT(imm19, 19, 5);

      _ Emit(b_cond_instr);
    } else if ((inst & PCRelAddressingMask) == ADRP) {
      uint64_t src_PAGE  = ALIGN(cur_src_pc, 0x1000);
      uint64_t dest_PAGE = ALIGN(cur_dest_pc, 0x1000);

      uint32_t immhi = bits(inst, 5, 23);
      uint32_t immlo = bits(inst, 29, 30);

      uint64_t imm = (LFT(immhi, 19, 2) | LFT(immlo, 2, 0)) << 12;

      uint64_t final_PAGE = src_PAGE + imm;

      imm   = final_PAGE - dest_PAGE;
      immhi = bits(imm >> 12, 2, 20);
      immlo = bits(imm >> 12, 0, 1);

      uint64_t tmp = (LFT(immhi, 19, 5) | LFT(immlo, 2, 29));
      if(tmp >= (1UL << 30)){ //adrp偏移4GB，这里粗略计算判断
        flag = true;
        break;
      }
      
      int32_t adrp_instr = (inst & 0x9f00001f) | LFT(immhi, 19, 5) | LFT(immlo, 2, 29);

      _ Emit(adrp_instr);
    } else {
      // origin write the instruction bytes
      _ Emit(inst);
    }

    // Move to next instruction
    cur_dest_pc += turbo_assembler_.GetCodeBuffer()->getSize() - off;
    cur_src_pc += 4;
    cur_addr += 4;
    inst = *(arm64_inst_t *)cur_addr;
  }

  if(flag){
    LOG("函数0x%llx不能被hook。\n", from_pc);
    ExecutableMemoryArena::Destory(codeChunk);//这里实际应该清理的
    return NULL;//返回NULL帮助外面判断
  }
  
  // Branch to the rest of instructions
  _ AdrpAddMov(x17, cur_dest_pc, cur_src_pc);
  _ br(x17);

  // Generate executable code
  CodePatch(turbo_assembler_.GetRealizeAddress(), turbo_assembler_.GetCodeBuffer()->getRawBuffer(),
            turbo_assembler_.GetCodeBuffer()->getSize());
  // Alloc a new AssemblyCode
  code = new AssemblyCode;
  code->initWithAddressRange((addr_t)turbo_assembler_.GetRealizeAddress(), turbo_assembler_.GetCodeBuffer()->getSize());

  if (code->raw_instruction_size() > codeChunk->size) {
    // free the codeChunk
    ExecutableMemoryArena::Destory(codeChunk);

    relo_code_chunk_size += chunk_size_step;
    codeChunk = ExecutableMemoryArena::AllocateCodeChunk(relo_code_chunk_size);
    to_pc     = (uint64_t)codeChunk->address;

    goto TryRelocateWithNewCodeChunkAgain;
  }

  return code;
}
