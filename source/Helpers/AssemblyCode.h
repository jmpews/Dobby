#ifndef ASSEMBLY_CODE_H
#define ASSEMBLY_CODE_H

#include "dobby_internal.h"

#include "core/modules/assembler/assembler.h"

using namespace zz;

class AssemblyCode {

public:
  void initWithAddressRange(addr_t address, int size);

  void reInitWithAddressRange(addr_t address, int size);

  // realize the buffer address to runtime code, and create a corresponding Code Object
  static AssemblyCode *FinalizeFromAddress(addr_t address, int size);

  // realize the buffer address to runtime code, and create a corresponding Code Object
  static AssemblyCode *FinalizeFromTurboAssember(AssemblerBase *assember);

  inline addr_t raw_instruction_start() {
    return (addr_t)range_.address;
  };

  inline int raw_instruction_size() {
    return range_.length;
  };

private:
  MemoryRange range_;
};

#endif
