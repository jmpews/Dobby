#include "relocator-arm.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RELOCATOR_INSTRUCIONS_SIZE 64

void arm_relocator_init(ARMRelocator *relocator, ARMReader *input, ARMAssemblerWriter *output)
{
    memset(relocator, 0, sizeof(ARMRelocator));
    relocator->needRelocateInputCount = 0;
    relocator->doneRelocateInputCount = 0;
    relocator->input = input;
    relocator->output = output;
    relocator->try_relocated_length = 0;
}

void arm_relocator_free(ARMRelocator *relocator)
{

    arm_reader_free(relocator->input);
    arm_writer_free(relocator->output);
    free(relocator);
}

void arm_relocator_reset(ARMRelocator *self, ARMReader *input, ARMAssemblerWriter *output)
{
    self->needRelocateInputCount = 0;
    self->doneRelocateInputCount = 0;
    self->input = input;
    self->output = output;
    self->literal_insnCTXs_count = 0;
    self->try_relocated_length = 0;
}

void arm_relocator_read_one(ARMRelocator *self, ARMInstruction *instruction)
{
    ARMInstruction *insn_ctx;

    arm_reader_read_one_instruction(self->input);

    // switch (1) {}

    self->needRelocateInputCount++;

    if (instruction != NULL)
        *instruction = *insn_ctx;
}

// try relocate to get relocate-insn-limit
void arm_relocator_try_relocate(zz_ptr_t address, zz_size_t min_bytes, zz_size_t *max_bytes)
{
    int tmp_size = 0;
    bool early_end = FALSE;
    zz_addr_t target_addr = (zz_addr_t)address;
    ARMInstruction *insn_ctx;
    ARMReader *reader = arm_reader_new(address);

    do
    {
        insn_ctx = arm_reader_read_one_instruction(reader);
        switch (GetARMInsnType(insn_ctx->insn))
        {
        case ARM_INS_B_A1:
        {
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

    if (early_end)
    {
        *max_bytes = tmp_size;
    }

    arm_reader_free(reader);
    return;
}

#if 0
zz_addr_t arm_relocator_get_insn_relocated_offset(ARMRelocator *self, zz_addr_t address) {
    const ZzInstruction *insn_ctx;
    const ;
    int i;
    for (i = 0; i < self->needRelocateInputCount; i++) {
        re_insn_ctx = &self->output_insnCTXs[i];
        insn_ctx    = re_insn_ctx->insn_ctx;
        if (insn_ctx->address == address && re_insn_ctx->relocated_offset) {
            return re_insn_ctx->relocated_offset;
        }
    }
    return 0;
}
#endif

static ARMRelocatorInstruction *arm_relocator_get_relocator_insn_with_address(ARMRelocator *self,
                                                                              zz_addr_t insn_address)
{
    for (int i = 0; i < self->relocated_insnCTXs_count; ++i)
    {
        if ((self->relocator_insnCTXs[i].origin_insn->pc - 8) == insn_address)
        {
            return &self->relocator_insnCTXs[i];
        }
    }
    return NULL;
}
void arm_relocator_relocate_writer(ARMRelocator *relocator, zz_addr_t final_relocate_address)
{
    ARMRelocatorInstruction *relocated_insn;
    if (relocator->literal_insnCTXs_count)
    {
        zz_addr_t *literal_target_address_ptr;
        for (int i = 0; i < relocator->literal_insnCTXs_count; i++)
        {
            literal_target_address_ptr = (zz_addr_t *)relocator->literal_insnCTXs[i]->address;
            // literal instruction in the range of instructions-need-fix
            if (*literal_target_address_ptr > (relocator->input->start_pc - 8) &&
                *literal_target_address_ptr < (relocator->input->start_pc - 8 + relocator->input->insns_size))
            {
                relocated_insn =
                    arm_relocator_get_relocator_insn_with_address(relocator, *literal_target_address_ptr);
                assert(relocated_insn);
                *literal_target_address_ptr =
                    (*relocated_insn->relocated_insnCTXs)->pc - relocator->output->start_pc + final_relocate_address;
            }
        }
    }
}

void arm_relocator_write_all(ARMRelocator *self)
{
    int count = 0;
    int doneRelocateInputCount = self->doneRelocateInputCount;
    ARMAssemblerWriter arm_writer = *self->output;

    while (arm_relocator_write_one(self))
        count++;
}

void arm_relocator_register_literal_insn(ARMRelocator *self, ARMInstruction *insn_ctx)
{
    self->literal_insnCTXs[self->literal_insnCTXs_count++] = insn_ctx;
    // convert the temportary absolute address with offset.
    //    zz_addr_t *temp_address = (zz_addr_t  *)insn_ctx->address;
    //    *temp_address = insn_ctx->pc - self->output->start_pc;
}

// PAGE: A8-312
static bool arm_relocator_rewrite_ADD_register_A1(ARMRelocator *self, const ARMInstruction *insn_ctx)
{
    uint32_t insn = insn_ctx->insn;

    uint32_t Rn_ndx, Rd_ndx, Rm_ndx;
    Rn_ndx = get_insn_sub(insn, 16, 4);
    Rd_ndx = get_insn_sub(insn, 12, 4);
    Rm_ndx = get_insn_sub(insn, 0, 4);

    if (Rn_ndx != ARM_REG_PC)
    {
        return FALSE;
    }
    // push R7
    arm_writer_put_push_reg(self->output, ARM_REG_R7);
    arm_writer_put_ldr_b_reg_address(self->output, ARM_REG_R7, insn_ctx->pc);
    arm_writer_put_instruction(self->output, (insn & 0xFFF0FFFF) | ARM_REG_R7 << 16);
    // pop R7
    arm_writer_put_pop_reg(self->output, ARM_REG_R7);
    return TRUE;
}

// PAGE: A8-410
static bool arm_relocator_rewrite_LDR_literal_A1(ARMRelocator *self, const ARMInstruction *insn_ctx)
{
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

    arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);
    arm_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    arm_writer_put_ldr_reg_reg_imm(self->output, Rt_ndx, Rt_ndx, 0);
    return TRUE;
}

// PAGE: A8-322
static bool arm_relocator_rewrite_ADR_A1(ARMRelocator *self, const ARMInstruction *insn_ctx)
{
    uint32_t insn = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;
    int Rt_ndx = get_insn_sub(insn, 12, 4);

    arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// PAGE: A8-322
static bool arm_relocator_rewrite_ADR_A2(ARMRelocator *self, const ARMInstruction *insn_ctx)
{
    uint32_t insn = insn_ctx->insn;
    uint32_t imm12 = get_insn_sub(insn, 0, 12);
    uint32_t imm32 = imm12;
    zz_addr_t target_address;
    target_address = insn_ctx->pc - imm32;
    int Rt_ndx = get_insn_sub(insn, 12, 4);

    arm_writer_put_ldr_b_reg_address(self->output, Rt_ndx, target_address);

    return TRUE;
}

// 0x000 : b.cond 0x0;
// 0x004 : b 0x4
// 0x008 : ldr pc, [pc, #0]
// 0x00c : .long 0x0
// 0x010 : remain code

// PAGE: A8-334
static bool arm_relocator_rewrite_B_A1(ARMRelocator *self, const ARMInstruction *insn_ctx)
{
    uint32_t insn = insn_ctx->insn;
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = imm24 << 2;
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    arm_writer_put_instruction(self->output, (insn & 0xFF000000) | 0);
    arm_writer_put_b_imm(self->output, 0x4);
    arm_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address);
    arm_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
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
static bool arm_relocator_rewrite_BLBLX_immediate_A1(ARMRelocator *self, const ARMInstruction *insn_ctx)
{
    uint32_t insn = insn_ctx->insn;
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = imm24 << 2;
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    // CurrentInstrSet = thumb
    // targetInstrSet = arm

    // convert 'bl' to 'b', but save 'cond'
    arm_writer_put_instruction(self->output, (insn & 0xF0000000) | 0b1010 << 24 | 0);
    arm_writer_put_b_imm(self->output, 0);
    arm_writer_put_ldr_b_reg_address(self->output, ARM_REG_LR, insn_ctx->pc - 4);
    arm_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    arm_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address);
    arm_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);

    return TRUE;
}

// PAGE: A8-348
static bool arm_relocator_rewrite_BLBLX_immediate_A2(ARMRelocator *self, const ARMInstruction *insn_ctx)
{
    uint32_t insn = insn_ctx->insn;
    uint32_t H = get_insn_sub(insn, 24, 1);
    uint32_t imm24 = get_insn_sub(insn, 0, 24);
    uint32_t imm32 = (imm24 << 2) | (H << 1);
    zz_addr_t target_address;
    target_address = insn_ctx->pc + imm32;

    arm_writer_put_ldr_b_reg_address(self->output, ARM_REG_LR, insn_ctx->pc - 4);
    // if(target_address > self->input->start_pc && target_address < (self->input->start_pc+ self->input->insns_size))
    arm_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);
    arm_writer_put_ldr_reg_address(self->output, ARM_REG_PC, target_address);
    arm_relocator_register_literal_insn(self, self->output->insnCTXs[self->output->insnCTXs_count - 1]);

    return TRUE;
}

bool arm_relocator_write_one(ARMRelocator *self)
{
    ARMInstruction *insn_ctx, **input_insnCTXs;
    ARMRelocatorInstruction *relocator_insn_ctx;
    zz_size_t tmp_size;
    relocator_insn_ctx = self->relocator_insnCTXs + self->relocated_insnCTXs_count;

    bool rewritten = FALSE;

    if (self->needRelocateInputCount != self->doneRelocateInputCount)
    {
        input_insnCTXs = self->input->insnCTXs;
        insn_ctx = input_insnCTXs[self->doneRelocateInputCount];
        relocator_insn_ctx->origin_insn = insn_ctx;
        relocator_insn_ctx->relocated_insnCTXs = self->output->insnCTXs + self->output->insnCTXs_count;
        relocator_insn_ctx->output_index_start = self->output->insnCTXs_count;
        tmp_size = self->output->insns_size;
        self->doneRelocateInputCount++;
        self->relocated_insnCTXs_count++;
    }
    else
        return FALSE;

    switch (GetARMInsnType(insn_ctx->insn))
    {
    case ARM_INS_ADD_register_A1:
        rewritten = arm_relocator_rewrite_ADD_register_A1(self, insn_ctx);
        break;
    case ARM_INS_LDR_literal_A1:
        rewritten = arm_relocator_rewrite_LDR_literal_A1(self, insn_ctx);
        break;
    case ARM_INS_ADR_A1:
        rewritten = arm_relocator_rewrite_ADR_A1(self, insn_ctx);
        break;
    case ARM_INS_ADR_A2:
        rewritten = arm_relocator_rewrite_ADR_A2(self, insn_ctx);
        break;
    case ARM_INS_B_A1:
        rewritten = arm_relocator_rewrite_B_A1(self, insn_ctx);
        break;
    case ARM_INS_BLBLX_immediate_A1:
        rewritten = arm_relocator_rewrite_BLBLX_immediate_A1(self, insn_ctx);
        break;
    case ARM_INS_BLBLX_immediate_A2:
        rewritten = arm_relocator_rewrite_BLBLX_immediate_A2(self, insn_ctx);
        break;
    case ARM_UNDEF:
        rewritten = FALSE;
        break;
    }
    if (!rewritten)
    {
        arm_writer_put_bytes(self->output, (char *)&insn_ctx->insn, insn_ctx->size);
    }
    else
    {
    }

    relocator_insn_ctx->size = self->output->insns_size - tmp_size;
    relocator_insn_ctx->ouput_index_end = self->output->insnCTXs_count;
    relocator_insn_ctx->relocated_insnCTXs_count = relocator_insn_ctx->ouput_index_end - relocator_insn_ctx->output_index_start;

    return TRUE;
}
