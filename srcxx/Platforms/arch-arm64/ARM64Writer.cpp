//
// Created by jmpews on 2018/6/14.
//

#include "ARM64Writer.h"
#include "MemoryManager.h"
#include <assert.h>
#include <string.h>

#include "ARM64Relocator.h"

inline void ReadBytes(void *data, void *address, int length) {
  memcpy(data, address, length);
}

ARM64AssemblerWriter::ARM64AssemblerWriter(void *pc) : pc(pc) {
  instBytes.reserve(1024);
}

void ARM64AssemblerWriter::reset(void *pc) {
  instBytes.clear();
  pc = pc;
}

void ARM64AssemblerWriter::PatchTo(void *target_address) {
  buffer = target_address;
  MemoryManager::CodePatch(target_address, instBytes.data(), instBytes.size());
}

// void ARM64AssemblerWriter::NearPatchTo(void *target_address, int range) {
//     buffer = target_address;
//     CodeCave *cc;
//     MemoryManager *mm = MemoryManager::GetInstance();
//     cc                = mm->searchNearCodeCave(target_address, range, instBytes.size());
//     MemoryManager::CodePatch((void *)cc->address, instBytes.data(), instBytes.size());
//     delete (cc);
// }

// void ARM64AssemblerWriter::RelocatePatchTo(ARM64Relocator *relocatorARM64, void *target_address) {
//     buffer = target_address;
//     CodeSlice *cs;
//     MemoryManager *mm = MemoryManager::GetInstance();
//     cs                = mm->allocateCodeSlice(instBytes.size());

//     relocatorARM64->doubleWrite(cs->data);

//     MemoryManager::CodePatch(cs->data, instBytes.data(), instBytes.size());

//     delete (cs);
// }

void ARM64AssemblerWriter::putBytes(void *data, int dataSize) {
  ARM64InstructionCTX *instCTX = new (ARM64InstructionCTX);

  assert(&instBytes[0] == instBytes.data());
  instCTX->pc      = (zz_addr_t)this->pc + this->instBytes.size();
  instCTX->address = (zz_addr_t)this->instBytes.data() + this->instBytes.size();
  instCTX->size    = 4;
  ReadBytes(&instCTX->bytes, (void *)instCTX->address, 4);

  ReadBytes(&instBytes[instBytes.size()], (void *)instCTX->address, 4);
  instBytes.resize(instBytes.size() + 4);

  instCTXs.push_back(instCTX);
}
