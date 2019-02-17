
#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

using namespace zz::arm64;

CodeBuffer *GenTrampoline(void *from, void *to) {

  TurboAssembler turbo_assembler_(from);
#define _ turbo_assembler_.

  _ adrp(X(17), stub_va);
  _ add(X(17), X(17), (addr_t)from % 0x4000);
  _ ldr(X(17), MemOperand(X(17), 0));
  _ br(X(17));

  return turbo_assembler_.GetCodeBuffer();
}
