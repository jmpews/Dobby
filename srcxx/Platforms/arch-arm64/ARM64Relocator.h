//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_ARM64RELOCATOR_H
#define HOOKZZ_ARM64RELOCATOR_H

#include "ARM64Reader.h"
#include "ARM64Writer.h"
#include "Instruction.h"

#include <iostream>
#include <map>
#include <vector>

class ARM64Relocator {

  public:
    int limitRelocateInstSize;
    int relocatedInstSize;
    int needRelocateInputCount;
    int doneRelocateInputCount;

    ARM64AssemblerWriter *output;
    ARM64AssemblyReader *input;

    // memory patch can't confirm the code slice length, so last setp of memory patch need repair the literal instruction.
    std::vector<ARM64InstructionCTX *> literalInstCTXs;
    std::map<int, int> indexRelocatedInputOutput;

  public:
    ARM64Relocator(ARM64AssemblyReader *input, ARM64AssemblerWriter *output);

    void reset();

    void tryRelocate(void *address, int bytes_min, int *bytes_max);

    void relocateTo(void *target_address);

    void doubleWrite(void *target_address);

    void registerLiteralInstCTX(ARM64InstructionCTX *instCTX);

    void relocateWrite();
    void relocateWriteAll();

    void rewrite_LoadLiteral(ARM64InstructionCTX *instCTX);
    void rewrite_BaseCmpBranch(ARM64InstructionCTX *instCTX);
    void rewrite_BranchCond(ARM64InstructionCTX *instCTX);
    void rewrite_B(ARM64InstructionCTX *instCTX);
    void rewrite_BL(ARM64InstructionCTX *instCTX);
};

#endif //HOOKZZ_ARM64RELOCATOR_H
