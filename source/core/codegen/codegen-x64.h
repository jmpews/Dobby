#pragma once

#include "core/codegen/codegen.h"
#include "core/assembler/assembler.h"
#include "core/assembler/assembler-x64.h"

namespace zz {
namespace x64 {

struct CodeGen : CodeGenBase {
  CodeGen(TurboAssembler *turbo_assembler) : CodeGenBase(turbo_assembler) {
  }

  void JmpNearIndirect(addr_t forward_stub_addr) {
    auto turbo_assembler_ = reinterpret_cast<TurboAssembler *>(this->assembler_);
#define _ turbo_assembler_->
#define __ turbo_assembler_->code_buffer_.
    uint64_t currIP = turbo_assembler_->CurrentIP() + 6;
    int32_t offset = (int32_t)(forward_stub_addr - currIP);

    // jmp *(rip + disp32)
    __ Emit<int8_t>(0xff);
    __ Emit<int8_t>(0x25); // ModR/M: 00 100 101
    __ Emit<int32_t>(offset);
  }
};

} // namespace x64
} // namespace zz