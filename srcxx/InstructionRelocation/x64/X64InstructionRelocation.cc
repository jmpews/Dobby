#include "globals.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/arch/x64/registers-x64.h"
#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

namespace zz {
namespace x64 {

typedef struct _PseudoLabelData {
  PseudoLabel label;
  uintptr_t address;
} PseudoLabelData;

AssemblyCode *GenRelocateCode(uint64_t src_address, int *relocate_size) {
  uint64_t src_ip = src_address;
  uint64_t cur_ip = src_ip;
  byte opcode1    = *(byte *)src_ip;

  std::vector<PseudoLabelData> labels;

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler.
  while ((cur_pc < (src_pc + *relocate_size))) {
    if (opcode1 == relo_call) {
    }
  }
}
} // namespace x64
} // namespace zz
