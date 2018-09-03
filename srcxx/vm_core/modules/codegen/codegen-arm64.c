#include "vm_core/modules/codegen/codegen-arm64.h"

#define _ assembler->
void CodeGen::LiteralFarBranch(uint64_t address) {
  PseudoLabel address_ptr;
  _ ldr(Register::X(17), &address_ptr);
  _ br(Register::X(17));
  _ PseudoBind(&address_ptr);
  _ EmitInt64(address);
}