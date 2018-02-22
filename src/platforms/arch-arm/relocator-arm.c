#include "relocator-arm.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void zz_arm_relocator_init(ZzARMRelocator *relocator, ZzARMReader *input, ZzARMAssemblerWriter *output) {
    memset(relocator, 0, sizeof(ZzARMRelocator));
    relocator->inpos = 0;
    relocator->outpos = 0;
    relocator->input = input;
    relocator->output = output;
    relocator->try_relocated_length = 0;
}

void zz_arm_relocator_free(ZzARMRelocator *relocator) {

    zz_arm_reader_free(relocator->input);
    zz_arm_writer_free(relocator->output);
    free(relocator);
}

void
zz_arm_relocator_reset(ZzARMRelocator *self, ZzARMReader *input, ZzARMAssemblerWriter *output) {
    self->inpos = 0;
    self->outpos = 0;
    self->input = input;
    self->output = output;
    self->literal_insn_size = 0;
    self->try_relocated_length = 0;
}

void zz_arm_relocator_read_one(ZzARMRelocator *self, ZzARMInstruction *instruction) {
    ZzARMInstruction *insn_ctx;

    zz_arm_reader_read_one_instruction(self->input);

    // switch (1) {}

    self->inpos++;

    if (instruction != NULL)
        *instruction = *insn_ctx;
}

// try relocate to get relocate-insn-limit
void zz_arm_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes) {
    int tmp_size = 0;
    bool early_end = FALSE;
    zz_addr_t target_addr = (zz_addr_t) address;
    ZzARMInstruction *insn_ctx;
    ZzARMReader *reader = zz_arm_reader_new(address);

    do {
        insn_ctx = zz_arm_reader_read_one_instruction(reader);
        switch (GetARMInsnType(insn_ctx->insn)) {
            case ARM_INS_B_A1: {
                uint32_t cond = get_insn_sub(insn_ctx->insn, 28, 4);
                if (cond == 0xE)
                    early_end = TRUE;
            };
                break;
            default:;
        }
        tmp_size += insn_ctx->size;
        target_addr = target_addr + insn_ctx->size;
    } while (tmp_size < min_bytes);

    if (early_end) {
        *max_bytes = tmp_size;
    }

    zz_arm_reader_free(reader);
    return;
}

#if 0
zz_addr_t zz_arm_relocator_get_insn_relocated_offset(ZzARMRelocator *self, zz_addr_t address) {
    const ZzInstruction *insn_ctx;
    const ;
    int i;
    for (i = 0; i < self->inpos; i++) {
        re_insn_ctx = &self->output_insns[i];
        insn_ctx    = re_insn_ctx->insn_ctx;
        if (insn_ctx->address == address && re_insn_ctx->relocated_offset) {
            return re_insn_ctx->relocated_offset;
        }
    }
    return 0;
}
#endif

static ZzARMRelocatorInstruction *zz_arm_relocator_get_relocator_insn_with_address(ZzARMRelocator *self, zz_addr_t insn_address) {
    for (int i = 0; i < self->relocator_insn_size; ++i) {
        if((self->relocator_insns[i].origin_insn->pc-8) == insn_address) {
            return &self->relocator_insns[i];
        }

    }
    return NULL;
}
void zz_arm_relocator_relocate_writer(ZzARMRelocator *relocator, zz_addr_t final_relocate_address) {
    ZzARMRelocatorInstruction *relocated_insn;
    if (relocator->literal_insn_size) {
        zz_addr_t *literal_target_address_ptr;
        for (int i = 0; i < relocator->literal_insn_size; i++) {
            literal_target_address_ptr = (zz_addr_t *)relocator->literal_insns[i]->address;
            // literal instruction in the range of instructions-need-fix
            if(*literal_target_address_ptr > (relocator->input->start_pc - 8) && *literal_target_address_ptr < (relocator->input->start_pc - 8+ relocator->input->size)) {
                relocated_insn = zz_arm_relocator_get_relocator_insn_with_address(relocator, *literal_target_address_ptr);
                assert(relocated_insn);
                *literal_target_address_ptr = (*relocated_insn->relocated_insns)->pc - relocator->output->start_pc + final_relocate_address;
            }
        }
    }
}



void zz_arm_relocator_write_all(ZzARMRelocator *self) {
    int count = 0;
    int outpos = self->outpos;
    ZzARMAssemblerWriter arm_writer = *self->output;

    while (zz_arm_relocator_write_one(self))
        count++;
}

void zz_arm_relocator_register_literal_insn(ZzARMRelocator *self, ZzARMInstruction *insn_ctx) {
    self->literal_insns[self->literal_insn_size++] = insn_ctx;
    // convert the temportary absolute address with offset.
//    zz_addr_t *temp_address = (zz_addr_t  *)insn_ctx->address;
//    *temp_address = insn_ctx->pc - self->output->start_pc;
}

// PAGE: A8-312
static bool
zz_arm_relocator_rewrite_ADD_register_A1(ZzARMRelocator *self, const ZzARMInstruction *insn_ctx
) {
    uint32_t insn = insn_ctx->insn;

    uint32_t Rn_ndx, Rd_ndx, Rm_ndx;
    Rn_ndx = get_insn_sub(insn, 16, 4);
    Rd_ndx = get_insn_sub(insn, 12, 4);
    Rm_ndx = get_insn_sub(insn, 0, 4);

    if (Rn_ndx != ZZ_ARM_REG_PC) {
        return FALSE;
    }
    // push R7
    zz_arm_writer_put_push_reg(self->output, ZZ_ARM_REG_R7);
    zz_arm_writer_put_ldr_b_reg_address(self->output, ZZ_ARM_REG_R7, insn_ctx->pc);
    zz_arm_writer_put_instruction(self->output, (insn & 0xFFF0FFFF) | ZZ_ARM_REG_R7 << 16);
    // pop R7
    zz_arm_writer_put_pop_reg(self->output, ZZ_ARM_REG_R7);
    return TRUE;
}

// PAGE: A8-410
static bool
zz_arm_relocator_rewrite_LDR_literal_A1(ZzARMRelocator *self, const ZzARMInstruction *insn_ctx
) {
    uint32_t insn = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    bool add = get_insn_sub(insn, 7 + 16, 1) == 1;
    zz_addr_t target_address;
    if (add)
        target_address = insn_ctx->pc + imm32;
    else
        target_address = insn_ctx->pc - imm32;
    int Rt_ndx = get_insn_sub(insn, 12, 4);

//    if(target_address > self->input->start_pc && target_address < (self->input->start_pc+ self->input->size)) {
//        ZZ_ERROR_LOG("instruction-fix-failed at %p", self->input->current_pc);
//    }

    zz_arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    zz_arm_relocator_register_literal_insn(self, self->output->insns[self->output->insn_size - 1]);
    zz_arm_writer_put_ldr_reg_reg_imm(self->output, Rt_ndx, Rt_ndx, 0);
    return TRUE;
}

// PAGE: A8-322
static bool zz_arm_relocator_rewrite_ADR_A1(ZzARMRelocator *self, const ZzARMInstruction *insn_ctx
) {
    uint32_t insn = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;
    int Rt_ndx = get_insn_sub(insn, 12, 4);

    zz_arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// PAGE: A8-322
static bool zz_arm_relocator_rewrite_ADR_A2(ZzARMRelocator *self, const ZzARMInstruction *insn_ctx
) {
    uint32_t insn = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    zz_addr_t target_address;
    target_address = insn_ctx->pc - imm32;
    int Rt_ndx = get_insn_sub(insn, 12, 4);

    zz_arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// 0x000 : b.cond 0x0;
// 0x004 : b 0x4
// 0x008 : ldr pc, [pc, #0]
// 0x00c : .long 0x0
// 0x010 : remain code

// PAGE: A8-334
static bool zz_arm_relocator_rewrite_B_A1(ZzARMRelocator *self, const ZzARMInstruction *insn_ctx
) {
    uint32_t insn = insn_ctx->insn;
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = imm24 << 2;
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    zz_arm_writer_put_instruction(self->output, (insn & 0xFF000000) | 0);
    zz_arm_writer_put_b_imm(self->output, 0x4);
    zz_arm_writer_put_ldr_reg_address(self->output, ZZ_ARM_REG_PC, target_address);
    zz_arm_relocator_register_literal_insn(self, self->output->insns[self->output->insn_size - 1]);
    return TRUE;
}

// 0x000 : bl.cond 0x0;

// 0x004 : b 0x10

// 0x008 : ldr lr, [pc, #0]
// 0x00c : b 0x0
// 0x010 : .long 0x0

// 0x014 : ldr pc, [pc, #0]
// 0x018 : .long 0x0

// 0x01c : remain code

// PAGE: A8-348
static bool
zz_arm_relocator_rewrite_BLBLX_immediate_A1(ZzARMRelocator *self, const ZzARMInstruction *insn_ctx
) {
    uint32_t insn = insn_ctx->insn;
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = imm24 << 2;
    zz_addr_t target_address;
    target_address = ALIGN_4(insn_ctx->pc) + imm32;

    // CurrentInstrSet = thumb
    // targetInstrSet = arm

    // convert 'bl' to 'b', but save 'cond'
    zz_arm_writer_put_instruction(self->output, (insn & 0xF0000000) | 0b1010 << 24 | 0);
    zz_arm_writer_put_b_imm(self->output, 0);
    zz_arm_writer_put_ldr_b_reg_address(self->output, ZZ_ARM_REG_LR, insn_ctx->pc - 4);
    zz_arm_relocator_register_literal_insn(self, self->output->insns[self->output->insn_size - 1]);
    zz_arm_writer_put_ldr_reg_address(self->output, ZZ_ARM_REG_PC, target_address);
    zz_arm_relocator_register_literal_insn(self, self->output->insns[self->output->insn_size - 1]);

    return TRUE;
}

// PAGE: A8-348
static bool
zz_arm_relocator_rewrite_BLBLX_immediate_A2(ZzARMRelocator *self, const ZzARMInstruction *insn_ctx
) {
    uint32_t insn = insn_ctx->insn;
    uint32_t H = get_insn_sub(insn, 24, 1);
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = (imm24 << 2) | (H << 1);
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    zz_arm_writer_put_ldr_b_reg_address(self->output, ZZ_ARM_REG_LR, insn_ctx->pc - 4);
    // if(target_address > self->input->start_pc && target_address < (self->input->start_pc+ self->input->size))
    zz_arm_relocator_register_literal_insn(self, self->output->insns[self->output->insn_size - 1]);
    zz_arm_writer_put_ldr_reg_address(self->output, ZZ_ARM_REG_PC, target_address);
    zz_arm_relocator_register_literal_insn(self, self->output->insns[self->output->insn_size - 1]);

    return TRUE;
}

bool zz_arm_relocator_write_one(ZzARMRelocator *self) {
    ZzARMInstruction *insn_ctx, **input_insns;
    ZzARMRelocatorInstruction *relocator_insn;
    zz_size_t tmp_size;
    relocator_insn = self->relocator_insns + self->relocator_insn_size;

    bool rewritten = FALSE;

    if (self->inpos != self->outpos) {
        input_insns = self->input->insns;
        insn_ctx    = input_insns[self->outpos];
        relocator_insn->origin_insn = insn_ctx;
        relocator_insn->relocated_insns = self->output->insns+self->output->insn_size;
        relocator_insn->output_index_start = self->output->insn_size;
        tmp_size = self->output->size;
        self->outpos++;
        self->relocator_insn_size++;
    } else
        return FALSE;


    switch (GetARMInsnType(insn_ctx->insn)) {
        case ARM_INS_ADD_register_A1:
            rewritten = zz_arm_relocator_rewrite_ADD_register_A1(self, insn_ctx);
            break;
        case ARM_INS_LDR_literal_A1:
            rewritten = zz_arm_relocator_rewrite_LDR_literal_A1(self, insn_ctx);
            break;
        case ARM_INS_ADR_A1:
            rewritten = zz_arm_relocator_rewrite_ADR_A1(self, insn_ctx);
            break;
        case ARM_INS_ADR_A2:
            rewritten = zz_arm_relocator_rewrite_ADR_A2(self, insn_ctx);
            break;
        case ARM_INS_B_A1:
            rewritten = zz_arm_relocator_rewrite_B_A1(self, insn_ctx);
            break;
        case ARM_INS_BLBLX_immediate_A1:
            rewritten = zz_arm_relocator_rewrite_BLBLX_immediate_A1(self, insn_ctx);
            break;
        case ARM_INS_BLBLX_immediate_A2:
            rewritten = zz_arm_relocator_rewrite_BLBLX_immediate_A2(self, insn_ctx);
            break;
        case ARM_UNDEF:
            rewritten = FALSE;
            break;
    }
    if (!rewritten) {
        zz_arm_writer_put_bytes(self->output, (char *) &insn_ctx->insn, insn_ctx->size);
    } else {

    }

    relocator_insn->size = self->output->size - tmp_size;
    relocator_insn->ouput_index_end = self->output->insn_size;
    relocator_insn->relocated_insn_size = relocator_insn->ouput_index_end-relocator_insn->output_index_start;

    return TRUE;
}
