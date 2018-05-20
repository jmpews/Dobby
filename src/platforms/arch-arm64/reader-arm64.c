#include "reader-arm64.h"

ARM64AssemblyReader *arm64_reader_new(zz_ptr_t insn_address) {
    ARM64AssemblyReader *reader = (ARM64AssemblyReader *)malloc0(sizeof(ARM64AssemblyReader));

    reader->start_pc       = (zz_addr_t)insn_address;
    reader->insns_buffer   = (zz_addr_t)insn_address;
    reader->insns_size     = 0;
    reader->insnCTXs_count = 0;
    return reader;
}

void arm64_reader_init(ARM64AssemblyReader *self, zz_ptr_t insn_address) { arm64_reader_reset(self, insn_address); }

void arm64_reader_reset(ARM64AssemblyReader *self, zz_ptr_t insn_address) {
    self->start_pc       = (zz_addr_t)insn_address;
    self->insns_buffer   = (zz_addr_t)insn_address;
    self->insns_size     = 0;
    self->insnCTXs_count = 0;
}

void arm64_reader_free(ARM64AssemblyReader *self) {
    if (self->insnCTXs_count) {
        for (int i = 0; i < self->insnCTXs_count; i++) {
            free(self->insnCTXs[i]);
        }
    }
    free(self);
}

ARM64InstructionCTX *arm64_reader_read_one_instruction(ARM64AssemblyReader *self) {
    ARM64InstructionCTX *insn_ctx          = (ARM64InstructionCTX *)malloc0(sizeof(ARM64InstructionCTX));
    zz_addr_t next_insn_address            = (zz_addr_t)self->insns_buffer + self->insns_size;
    zz_addr_t next_pc                      = (zz_addr_t)self->start_pc + self->insns_size;
    insn_ctx->pc                           = next_pc;
    insn_ctx->address                      = next_insn_address;
    insn_ctx->insn                         = *(uint32_t *)next_insn_address;
    insn_ctx->size                         = 4;
    self->insnCTXs[self->insnCTXs_count++] = insn_ctx;
    self->insns_size += insn_ctx->size;
    return insn_ctx;
}

extern ARM64InstructionID ARM64InstructionIDTable[256];

ARM64InstID GetARM64InsnType(uint32_t insn) {
    ARM64InstructionID *instructionIDTable = ARM64InstructionIDTable;
    for (int i = 0; instructionIDTable[i].inst != 0 && i < 256; i++) {
        if ((insn & instructionIDTable[i].inst) == instructionIDTable[i].inst) {
            return instructionIDTable[i].InstID;
        }
    }
    return UNKNOWN;
}