#ifndef ZZ_MODULES_CODEGEN_CODGEN_H_
#define ZZ_MODULES_CODEGEN_CODGEN_H_

#include "vm_core/modules/assembler/assembler.h"

class CodeGenBase {
public:
  CodeGenBase(assembler) : assembler(assembler);

public:
  Assembler *assembler;

private:
}

#endif