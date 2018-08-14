//
// Created by jmpews on 2018/6/14.
//

#include "ARM64Relocator.h"
#include <assert.h>

ARM64Relocator::ARM64Relocator(ARM64AssemblyReader *input, ARM64AssemblerWriter *output) {
  input  = input;
  output = output;
}

void ARM64Relocator::reset() {
  output->reset(0);
  input->reset(0, 0);
  literalInstCTXs.clear();
  indexRelocatedInputOutput.clear();
}

void ARM64Relocator::tryRelocate(void *address, int bytes_min, int *bytes_max) {
  int tmpSize   = 0;
  bool earlyEnd = false;

  ARM64InstructionCTX *instCTX;

  ARM64AssemblyReader *reader = new ARM64AssemblyReader(address, address);

  do {
    instCTX = reader->readInstruction();
    switch (getInstType(instCTX->bytes)) {
    case BImm:
      earlyEnd = true;
      break;
    default:;
    }
    tmpSize += instCTX->size;

  } while (tmpSize < bytes_min);

  if (earlyEnd) {
    *bytes_max = bytes_min;
  }
  delete (reader);
}

void ARM64Relocator::relocateTo(void *target_address) {
  for (auto instCTX : literalInstCTXs) {
    zz_addr_t literal_target_address;
    literal_target_address = *(zz_addr_t *)instCTX->address;
    if (literal_target_address > (zz_addr_t)input->pc &&
        literal_target_address < ((zz_addr_t)input->pc + input->instBytes.size())) {
      for (auto it : indexRelocatedInputOutput) {
        ARM64InstructionCTX *inputInstCTX = input->instCTXs[it.first];
        if (inputInstCTX->address == literal_target_address) {
          *(zz_addr_t *)instCTX->address =
              output->instCTXs[it.second]->pc - (zz_addr_t)output->pc + (zz_addr_t)target_address;
          break;
        }
      }
    }
  }
}

void ARM64Relocator::doubleWrite(void *target_address) {
  assert((zz_addr_t)target_address % 4 == 0);

  int originInstByteSize = output->instBytes.size();
  output->reset(0);

  literalInstCTXs.clear();
  indexRelocatedInputOutput.clear();
  relocateWriteAll();

  void *noNeedRelocateInstBuffer = output->instBytes.data() + output->instBytes.size();

  output->putBytes(noNeedRelocateInstBuffer, originInstByteSize - output->instBytes.size());
}

void ARM64Relocator::registerLiteralInstCTX(ARM64InstructionCTX *instCTX) {
  literalInstCTXs.push_back(instCTX);
}

void ARM64Relocator::relocateWriteAll() {
  do {
    relocateWrite();
  } while (indexRelocatedInputOutput.size() < input->instCTXs.size());
}

void ARM64Relocator::relocateWrite() {
  ARM64InstructionCTX *instCTX;
  bool rewritten = true;

  int doneRelocatedCount;
  doneRelocatedCount = indexRelocatedInputOutput.size();

  if (input->instCTXs.size() < indexRelocatedInputOutput.size()) {
    instCTX = input->instCTXs[doneRelocatedCount];
  } else
    return;

  switch (getInstType(instCTX->bytes)) {
  case LoadLiteral:
    rewrite_LoadLiteral(instCTX);
    break;
  case BaseCmpBranch:
    rewrite_BaseCmpBranch(instCTX);
    break;
  case BranchCond:
    rewrite_BranchCond(instCTX);
    break;
  case B:
    rewrite_B(instCTX);
    break;
  case BL:
    rewrite_BL(instCTX);
    break;

  default:
    rewritten = false;
    break;
  }
  if (!rewritten) {
    output->putBytes((void *)&instCTX->bytes, instCTX->size);
  }

  indexRelocatedInputOutput.insert(std::pair<int, int>(doneRelocatedCount, output->instCTXs.size()));
}

inline uint32_t get_insn_sub(uint32_t insn, int start, int length) {
  return (insn >> start) & ((1 << length) - 1);
}

void ARM64Relocator::rewrite_LoadLiteral(ARM64InstructionCTX *instCTX) {
  uint32_t Rt, label;
  int index;
  zz_addr_t target_address;
  Rt             = get_insn_sub(instCTX->bytes, 0, 5);
  label          = get_insn_sub(instCTX->bytes, 5, 19);
  target_address = (label << 2) + instCTX->pc;

  /*
        0x1000: ldr Rt, #0x8
        0x1004: b #0xc
        0x1008: .long 0x4321
        0x100c: .long 0x8765
        0x1010: ldr Rt, Rt
    */
  ARM64Reg regRt = DisDescribeARM64Reigster(Rt, 0);
  output->put_ldr_reg_imm(regRt, 0x8);
  output->put_b_imm(0xc);
  registerLiteralInstCTX(output->instCTXs[output->instCTXs.size()]);
  output->putBytes((zz_ptr_t)&target_address, sizeof(target_address));
  output->put_ldr_reg_reg_offset(regRt, regRt, 0);
};

void ARM64Relocator::rewrite_BaseCmpBranch(ARM64InstructionCTX *instCTX) {
  uint32_t target;
  uint32_t inst32;
  zz_addr_t target_address;

  inst32 = instCTX->bytes;

  target         = get_insn_sub(inst32, 5, 19);
  target_address = (target << 2) + instCTX->pc;

  target = 0x8 >> 2;
  BIT32SET(&inst32, 5, 19, target);
  output->putBytes(&inst32, instCTX->size);

  output->put_b_imm(0x14);
  output->put_ldr_reg_imm(ARM64_REG_X17, 0x8);
  output->put_br_reg(ARM64_REG_X17);
  registerLiteralInstCTX(output->instCTXs[output->instCTXs.size()]);
  output->putBytes((zz_ptr_t)&target_address, sizeof(zz_ptr_t));
};

void ARM64Relocator::rewrite_BranchCond(ARM64InstructionCTX *instCTX) {
  uint32_t target;
  uint32_t inst32;
  zz_addr_t target_address;

  inst32 = instCTX->bytes;

  target         = get_insn_sub(inst32, 5, 19);
  target_address = (target << 2) + instCTX->pc;

  target = 0x8 >> 2;
  BIT32SET(&inst32, 5, 19, target);
  output->putBytes(&inst32, instCTX->size);

  output->put_b_imm(0x14);
  output->put_ldr_reg_imm(ARM64_REG_X17, 0x8);
  output->put_br_reg(ARM64_REG_X17);
  registerLiteralInstCTX(output->instCTXs[output->instCTXs.size()]);
  output->putBytes((zz_ptr_t)&target_address, sizeof(zz_ptr_t));
};

void ARM64Relocator::rewrite_B(ARM64InstructionCTX *instCTX) {
  uint32_t addr;
  zz_addr_t target_address;

  addr = get_insn_sub(instCTX->bytes, 0, 26);

  target_address = (addr << 2) + instCTX->pc;

  output->put_ldr_reg_imm(ARM64_REG_X17, 0x8);
  output->put_br_reg(ARM64_REG_X17);
  registerLiteralInstCTX(output->instCTXs[output->instCTXs.size()]);
  output->putBytes((zz_ptr_t)&target_address, sizeof(zz_ptr_t));
}

void ARM64Relocator::rewrite_BL(ARM64InstructionCTX *instCTX) {
  uint32_t op, addr;
  zz_addr_t target_address, next_pc_address;

  addr = get_insn_sub(instCTX->bytes, 0, 26);

  target_address  = (addr << 2) + instCTX->pc;
  next_pc_address = instCTX->pc + 4;

  output->put_ldr_reg_imm(ARM64_REG_X17, 0xc);
  output->put_blr_reg(ARM64_REG_X17);
  output->put_b_imm(0xc);
  registerLiteralInstCTX(output->instCTXs[output->instCTXs.size()]);
  output->putBytes((zz_ptr_t)&target_address, sizeof(zz_ptr_t));

  output->put_ldr_reg_imm(ARM64_REG_X17, 0x8);
  output->put_br_reg(ARM64_REG_X17);
  registerLiteralInstCTX(output->instCTXs[output->instCTXs.size()]);
  output->putBytes((zz_ptr_t)&next_pc_address, sizeof(zz_ptr_t));
}