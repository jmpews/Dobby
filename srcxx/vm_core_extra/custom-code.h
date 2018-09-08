#ifndef HOOKZZ_CUSTOM_CODE_H_
#define HOOKZZ_CUSTOM_CODE_H_

#include "vm_core/objects/code.h"
#include "vm_core/modules/assembler/assembler.h"

class AssemblerCode : public zz::Code {
public:
  static AssemblerCode *FinalizeTurboAssembler(zz::AssemblerBase *assembler);
};

#endif