//
// Created by jmpews on 2018/6/14.
//

#ifndef HOOKZZ_READERARM64_H
#define HOOKZZ_READERARM64_H

#include "ARM64AssemblyCore.h"
#include "Instruction.h"
#include "hookzz.h"

#include <istream>
#include <streambuf>
#include <vector>

class ARM64AssemblyReader {

public:
  void *start_pc;
  void *start_address;
  std::vector<ARM64InstructionCTX *> instCTXs;
  std::vector<char> instBytes;

public:
  ARM64AssemblyReader(void *address, void *pc);

  void reset(void *address, void *pc);

  ARM64InstructionCTX *readInstruction();
};

#endif //HOOKZZ_READERARM64_H
