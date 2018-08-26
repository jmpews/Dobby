#include "src/arch/arm64/assembler-arm64.h"

namespace zz {
namespace arm64 {

Assembler::Assembler() {
}

void Assembler::Emit(int32_t value) {
  buffer_->Emit(value);
}

TurboAssembler::TurboAssembler(Assembler &assembler) {
  assembler_ = assembler;
}

} // namespace arm64
} // namespace zz