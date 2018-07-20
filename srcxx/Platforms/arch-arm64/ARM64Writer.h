//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_ARM64WRITER_H
#define HOOKZZ_ARM64WRITER_H

#include "ARM64Register.h"
#include "Instruction.h"

#include <vector>

class ARM64Relocator;
class ARM64AssemblerWriter {
public:
  void *start_pc;
  void *start_address;
  std::vector<ARM64InstructionCTX *> instCTXs;
  std::vector<char> instBytes;

public:
  ARM64AssemblerWriter(void *pc);

  void reset(void *pc);

  void PatchTo(void *target_address);

  void putBytes(void *data, int dataSize);

  void put_ldr_reg_imm(ARM64Reg reg, uint32_t offset) {
    ARM64RegInfo ri;
    DescribeARM64Reigster(reg, &ri);

    uint32_t imm19, Rt;
    imm19         = offset >> 2;
    Rt            = ri.index;
    uint32_t inst = 0x58000000 | imm19 << 5 | Rt;

    putBytes((void *)&inst, 4);
  }

  void put_str_reg_reg_offset(ARM64Reg src_reg, ARM64Reg dst_reg, uint64_t offset) {

    ARM64RegInfo rs, rd;
    DescribeARM64Reigster(src_reg, &rs);
    DescribeARM64Reigster(dst_reg, &rd);

    uint32_t size, v = 0, opc = 0, Rn_ndx, Rt_ndx;
    Rn_ndx = rd.index;
    Rt_ndx = rs.index;

    if (rs.isInteger) {
      size = (rs.width == 64) ? 0b11 : 0b10;
    }

    uint32_t imm12 = offset >> size;
    uint32_t inst  = 0x39000000 | size << 30 | opc << 22 | imm12 << 10 | Rn_ndx << 5 | Rt_ndx;
    putBytes((void *)&inst, 4);
  }

  void put_ldr_reg_reg_offset(ARM64Reg dst_reg, ARM64Reg src_reg, uint64_t offset) {
    ARM64RegInfo rs, rd;
    DescribeARM64Reigster(src_reg, &rs);
    DescribeARM64Reigster(dst_reg, &rd);

    uint32_t size, v = 0, opc = 0b01, Rn_ndx, Rt_ndx;
    Rn_ndx = rs.index;
    Rt_ndx = rd.index;

    if (rs.isInteger) {
      size = (rs.width == 64) ? 0b11 : 0b10;
    }

    uint32_t imm12 = offset >> size;
    uint32_t inst  = 0x39000000 | size << 30 | opc << 22 | imm12 << 10 | Rn_ndx << 5 | Rt_ndx;
    putBytes((void *)&inst, 4);
  }

  void put_br_reg(ARM64Reg reg) {
    ARM64RegInfo ri;
    DescribeARM64Reigster(reg, &ri);

    uint32_t op   = 0, Rn_ndx;
    Rn_ndx        = ri.index;
    uint32_t inst = 0xd61f0000 | op << 21 | Rn_ndx << 5;
    putBytes((void *)&inst, 4);
  }

  void put_blr_reg(ARM64Reg reg) {
    ARM64RegInfo ri;
    DescribeARM64Reigster(reg, &ri);

    uint32_t op = 0b01, Rn_ndx;

    Rn_ndx        = ri.index;
    uint32_t inst = 0xd63f0000 | op << 21 | Rn_ndx << 5;
    putBytes((void *)&inst, 4);
  }

  void put_b_imm(uint64_t offset) {
    uint32_t op   = 0b0, imm26;
    imm26         = (offset >> 2) & 0x03ffffff;
    uint32_t inst = 0x14000000 | op << 31 | imm26;
    putBytes((void *)&inst, 4);
  }
};

#endif //HOOKZZ_ARM64WRITER_H
