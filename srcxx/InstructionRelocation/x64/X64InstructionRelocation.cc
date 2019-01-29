#include "globals.h"

#include "InstructionRelocation/x64/X64InstructionRelocation.h"

#include "core/arch/x64/registers-x64.h"
#include "core/modules/assembler/assembler-x64.h"
#include "core/modules/codegen/codegen-x64.h"

#include "InstructionRelocation/x64/X64IPRelativeOpcodeTable.h"

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

  InstrMnemonic *instr;

  TurboAssembler turbo_assembler_;
#define _ turbo_assembler.
  while ((cur_ip < (src_ip + *relocate_size))) {
    OpcodeDecodeItem *decodeItem = &OpcodeDecodeTable[opcode1];
    decodeItem->DecodeHandler(instr, demoItem, cur_ip);

  }
}
} // namespace x64
} // namespace zz
