#include "platform_macro.h"
#if defined(TARGET_ARCH_X64)

#include "dobby_internal.h"

#include "core/assembler/assembler-x64.h"
#include "core/codegen/codegen-x64.h"

#include "InstructionRelocation/x64/InstructionRelocationX64.h"

#include "MemoryAllocator/NearMemoryArena.h"
#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"

using namespace zz::x64;

static void **AllocIndirectStub(addr_t branch_address) {
  DataBlock *forwardStub = nullptr;
  forwardStub = NearMemoryArena::SharedInstance()->allocNearDataBlock((addr_t)branch_address, (size_t)2 * 1024 * 1024 * 1024, (int)sizeof(void *));
  if (forwardStub == nullptr) {
    ERROR_LOG("Not found near forward stub");
    return nullptr;
  }

  return (void **)forwardStub->addr;
}

CodeBufferBase *GenerateNormalTrampolineBuffer(addr_t from, addr_t to) {
  TurboAssembler turbo_assembler_((void *)from);
#define _ turbo_assembler_.

  // branch
  void **branch_stub = AllocIndirectStub(from);
  *branch_stub = (void *)to;

  CodeGen codegen(&turbo_assembler_);
  codegen.JmpNearIndirect((uint64_t)branch_stub);

  CodeBufferBase *result = NULL;
  result = turbo_assembler_.GetCodeBuffer()->Copy();
  return result;
}

CodeBufferBase *GenerateNearTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) {
  DLOG(0, "x64 near branch trampoline enable default");
  return NULL;
}

#endif