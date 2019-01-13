#include "code-buffer-arm64.h"

arm64_inst_t CodeBuffer::LoadInst(int offset) { return *static_cast<int32_t *>(buffer_ + offset); }

void RewriteInst(int offset, arm64_inst_t inst);

void EmitInst(int offset, arm64_inst_t inst);

void Emit64(int64_t data);
