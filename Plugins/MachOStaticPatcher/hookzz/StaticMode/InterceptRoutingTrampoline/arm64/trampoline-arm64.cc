
#include "core/modules/assembler/assembler-arm64.h"
#include "core/modules/codegen/codegen-arm64.h"

using namespace zz::arm64;

CodeBuffer *GenTrampoline(void *from, void *to) {

  TurboAssembler turbo_assembler_(from);
#define _ turbo_assembler_.
  
  uint64_t from_PAGE = ALIGN(from , 0x1000);
  uint64_t to_PAGE = ALIGN(to, 0x1000);
  uint64_t to_PAGEOFF = (uint64_t)to % 0x1000;
  
  _ adrp(X(17), to_PAGE - from_PAGE);
  _ add(X(17), X(17), to_PAGEOFF);
  _ ldr(X(17), MemOperand(X(17), 0));
  _ br(X(17));

  return turbo_assembler_.GetCodeBuffer();
}
