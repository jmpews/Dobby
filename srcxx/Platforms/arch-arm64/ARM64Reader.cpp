//
// Created by jmpews on 2018/6/14.
//

#include "ARM64Reader.h"
#include <assert.h>
#include <string.h>

inline void ReadBytes(void *data, void *address, int length) {
  memcpy(data, address, length);
}

ARM64AssemblyReader::ARM64AssemblyReader(void *address, void *pc) : start_address(address), start_pc(pc) {
  instBytes.reserve(1024);
}

void ARM64AssemblyReader::reset(void *address, void *pc) {
  instBytes.clear();
  start_address = address;
  start_pc      = pc;
}

ARM64InstructionCTX *ARM64AssemblyReader::readInstruction() {
  ARM64InstructionCTX *instCTX = new (ARM64InstructionCTX);

  assert(&instBytes[0] == instBytes.data());
  instCTX->pc      = (zz_addr_t)this->start_pc + this->instBytes.size();
  instCTX->address = (zz_addr_t)this->instBytes.data() + this->instBytes.size();
  instCTX->size    = 4;
  ReadBytes(&instCTX->bytes, (void *)instCTX->address, 4);

  ReadBytes(&instBytes[instBytes.size()], (void *)instCTX->address, 4);
  instBytes.resize(instBytes.size() + 4);

  instCTXs.push_back(instCTX);
  return instCTX;
}