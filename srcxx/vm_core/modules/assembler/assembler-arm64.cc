#include "vm_core/modules/assembler/assembler-arm64.h"

namespace zz {
namespace arm64 {

Assembler::Assembler() {
}

void Assembler::Emit(int32_t value) {
  buffer_.Emit(value);
}

void Assembler::EmitInt64(uint64_t value) {
  buffer_.Emit64(value);
}

void Assembler::bind(Label *label) {
  const intptr_t bound_pc = pc_offset();
  while (label->is_linked()) {
    int linkpos    = label->pos();
    int32_t inst32 = buffer_.Load32(linkpos);

    int prevlinkpos = 0;
    if ((inst32 & UnconditionalBranchMask) == UnconditionalBranchFixed) {
      // TODO
      // prevlinkpos = UnconditionalBranchOp_offset(inst32);
    }

    if (prevlinkpos == kStartOfLabelLinkChain) {
      label->link_to(prevlinkpos);
    }
  }
  label->bind_to(bound_pc);
}

int Assembler::LinkAndGetByteOffsetTo(Label *label) {
  int offset;

  if (label->is_bound()) {

    // The label is bound, so it does not need to be updated. Referring
    // instructions must link directly to the label as they will not be
    // updated.
    //
    // In this case, label->pos() returns the offset of the label from the
    // start of the buffer.
    //
    // Note that offset can be zero for self-referential instructions. (This
    // could be useful for ADR, for example.)
    offset = label->pos() - pc_offset();
  } else {
    if (label->is_linked()) {
      // The label is linked, so the referring instruction should be added onto
      // the end of the label's link chain.
      //
      // In this case, label->pos() returns the offset of the last linked
      // instruction from the start of the buffer.
      offset = label->pos() - pc_offset();
    } else {
      // The label is unused, so it now becomes linked and the referring
      // instruction is at the start of the new link chain.
      offset = kStartOfLabelLinkChain;
    }
    // The instruction at pc is now the last link in the label's chain.
    label->link_to(pc_offset());
  }
  return offset;
}

} // namespace arm64
} // namespace zz