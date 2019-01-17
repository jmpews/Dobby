#ifndef ZZ_MODULES_CODEGEN_CODEGEN_H_
#define ZZ_MODULES_CODEGEN_CODEGEN_H_

#include "core/modules/assembler/assembler.h"

#include <iostream>

using namespace zz;

class CodeGenBase {
public:
  CodeGenBase(AssemblerBase *assembler) : assembler_(assembler) {
  }

protected:
  AssemblerBase *assembler_;
};

#endif