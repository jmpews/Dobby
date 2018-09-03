#ifndef ZZ_MODULES_CODEGEN_CODEGEN_H_
#define ZZ_MODULES_CODEGEN_CODEGEN_H_

#include "vm_core/modules/assembler/assembler.h"

#include <iostream>

class Assembler;

class CodeGenBase {
public:
  CodeGenBase(Assembler *assembler) : assembler(assembler) {

  }

public:
  Assembler *assembler;

};

#endif