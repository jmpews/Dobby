#include "interceptor.h"

#define INSTRUCTION_IS_THUMB(insn_addr) ((insn_addr & 0x1) == 0x1)

#define ZZ_THUMB_TINY_REDIRECT_SIZE 16
#define ZZ_THUMB_FULL_REDIRECT_SIZE 16
#define ZZ_ARM_TINY_REDIRECT_SIZE 16
#define ZZ_ARM_FULL_REDIRECT_SIZE 16

typedef struct _ZzArmInterceptorBackend {
    ZzAllocator *allocator;
    ZzArmRelocator arm_relocator;
    ZzThumbRelocator thumb_relocator;

    ZzArmWriter arm_writer;
    ZzThumbWriter arm_writer;

    zpinter enter_thunk;
    zpointer leave_thunk;
} _ZzInterceptorBackend;

typedef struct _ZzArmHookFuntionEntryBackend {
    zbool is_thumb;
    zuint redirect_code_size;
} ZzArmHookFunctionEntryBackend;

// 1. confirm enter trampoline jump type. `abs jump` or `near jump`
// 2. confirm relocator need length
ZZSTATUS ZzPrepareTrampoline(ZzInterceptorBackend *self,
                             ZzHookFunctionEntry *entry) {
    zbool is_thumb = false;
    zpointer target_addr = entry->target_ptr;
    zuint redirect_limit;
    ZzArmHookFunctionEntryBackend *entry_backend =
        (ZzArmHookFunctionEntryBackend *)entry->backend;
    if (is_thumb) {
        if (entry->try_near_jump) {
            self->redirect_code_size = ZZ_THUMB_TINY_REDIRECT_SIZE;
        } else {
            zz_thumb_relocator_try_relocate(
                target_addr, ZZ_THUMB_FULL_REDIRECT_SIZE, &redirect_limit);
            self->redirect_code_size = ZZ_THUMB_FULL_REDIRECT_SIZE
        }
    } else {
        if (entry->try_near_jump) {
            self->redirect_code_size = ZZ_ARM_FULL_REDIRECT_SIZE;
        } else {
            zz_arm_relocator_try_relocate(
                target_addr, ZZ_ARM_FULL_REDIRECT_SIZE, &redirect_limit);
            self->redirect_code_size = ZZ_ARM_FULL_REDIRECT_SIZE;
        }
    }

    zz_arm_relocator_init(&self->arm_relocator, target_addr, &self->arm_writer);
    zz_thumb_relocator_init(&self->thumb_relocator, target_addr,
                            &self->thumb_writer);
}

ZZSTATUS ZzBuildEnterTrampoline(ZzInterceptorBackend *self,
                                ZzHookFunctionEntry *entry) {
    zbyte temp_codeslice_data[256];
    ZzArmWriter *arm_writer;
    ZzArmWriter *thumb_writer;
    ZzCodeSlice *code_slice;
    ZzArmHookFunctionEntryBackend *entry_backend;
    ZZSTATUS status;
    zbool is_thumb;
    zpointer target_addr = self->target_ptr;

    is_thumb = INSTRUCTION_IS_THUMB(target_addr);

    /* put data to stack */
    zz_arm_writer_put_sub_reg_reg_imm(writer, ARM_REG_SP, ARM_REG_SP, 3 * 4);
    zz_arm_writer_put_str_reg_reg_offset(writer, ARM_REG_R7, ARM_REG_SP, 0 * 4);

    zz_arm_writer_put_ldr_reg_address(writer, ARM_REG_R7, hookentry_ptr);
    zz_arm_writer_put_str_reg_reg_offset(writer, ARM_REG_R7, ARM_REG_SP, 2 * 4);

    zz_arm_writer_put_ldr_reg_reg_offset(writer, ARM_REG_R7, ARM_REG_SP, 0 * 4);
    zz_arm_writer_put_add_reg_reg_imm(writer, ARM_REG_SP, ARM_REG_SP, 4);

    zz_arm_writer_put_ldr_reg_address(writer, ARM_REG_PC, enter_thunk_ptr);

    if (is_thumb &&
        entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {

        code_slice =
            ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                               zz_thumb_writer_near_jump_range_size(),
                               writer->size); // @common-function
        if (!code_slice)
            return ZZ_FAILED;
    }

    if (!is_thumb &&
        entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE) {
        code_slice =
            ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                               zz_arm_writer_near_jump_range_size(),
                               writer->size); // @common-function
        if (!code_slice)
            return ZZ_FAILED;
    }

    code_slice =
        ZzNewCodeSlice(self->allocator, writer->size); // @common-funciton
    if (!code_slice)
        return ZZ_FAILED;

    if (!ZzMemoryPatchCode((zaddr)code_slice->data, temp_codeslice_data,
                           writer->size))
        return ZZ_FAILED;
    entry->on_enter_trampoline = code_slice->data;
    status = ZZ_SUCCESS;

    free(writer);
    return status;
}

ZZSTATUS ZzBuildInvokeTrampoline(ZzInterceptorBackend *self,
                                 ZzHookFunctionEntry *entry) {
    zbyte temp_codeslice_data[256];
    ZzCodeSlice *code_slice;
    ZzInterceptor *interceptor;

    ZzArmHookFunctionEntryBackend *entry_backend =
        (ZzArmHookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status;
    zbool is_thumb;
    zpointer target_addr = self->target_ptr;

    is_thumb = INSTRUCTION_IS_THUMB(target_addr);

    if (is_thumb) {
        ZzThumbRelocator *thumb_relocator;
        ZzThumbWriter *thumb_writer;
        thumb_relocator = &self->thumb_relocator;
        thumb_writer = &self->thumb_writer;
        zz_thumb_writer_reset(thumb_writer, temp_codeslice_data);

        do {
            zz_thumb_relocator_read_one(thumb_relocator, NULL);
        } while (thumb_relocator->input_cur - thumb_relocator->input_start <
                 self->redirect_code_size)

            zz_thumb_writer_put_ldr_reg_address(
                thumb_writer, target_addr + thumb_relocator->input_cur -
                                  thumb_relocator->input_start);
    } else {

        ZzArmRelocator *arm_relocator;
        ZzArmWriter *arm_writer;
        arm_relocator = &self->arm_relocator;
        arm_writer = &self->arm_writer;

        zz_arm_writer_reset(&self->arm_writer) do {

            zz_arm_relocator_read_one(&self->arm_relocator, NULL);
        }
        while (arm_relocator->input_cur - arm_relocator->input_start <
               self->redirect_code_size)
            ;

        zz_arm_writer_put_ldr_reg_address(
            arm_writer, target_addr + arm_relocator->input_cur -
                            arm_relocator->input_start);
    }

    code_slice = ZzNewCodeSlice(self->allocator,
                                relocate_writer->size); // @common-function

    if (entry->hook_type == HOOK_ADDRESS_TYPE) {

        // update target_half_ret_addr
        entry->target_half_ret_addr += (zaddr)code_slice->data;
    }

    if (!ZzMemoryPatchCode((zaddr)code_slice->data, temp_codeslice_data,
                           writer->size))
        return ZZ_FAILED;

    entry->on_invoke_trampoline = code_slice->data;

    return status;
}

ZZSTATUS ZzBuildLeaveTrampoline(ZzInterceptorBackend *self,
                                ZzHookFunctionEntry *entry) {
    zbyte temp_codeslice_data[256];
    ZzCodeSlice *code_slice;
    ZzInterceptor *interceptor;

    ZzArmHookFunctionEntryBackend *entry_backend =
        (ZzArmHookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status;
    zbool is_thumb;
    zpointer target_addr = self->target_ptr;

    /* put data to stack */
    zz_thumb_writer_put_sub_reg_reg_imm(writer, ARM_REG_SP, ARM_REG_SP, 3 * 4);
    zz_thumb_writer_put_str_reg_reg_offset(writer, ARM_REG_R7, ARM_REG_SP,
                                           0 * 4);

    zz_thumb_writer_put_ldr_reg_address(writer, ARM_REG_R7, hookentry_ptr);
    zz_thumb_writer_put_str_reg_reg_offset(writer, ARM_REG_R7, ARM_REG_SP,
                                           2 * 4);

    zz_thumb_writer_put_ldr_reg_reg_offset(writer, ARM_REG_R7, ARM_REG_SP,
                                           0 * 4);
    zz_thumb_writer_put_add_reg_reg_imm(writer, ARM_REG_SP, ARM_REG_SP, 4);

    zz_thumb_writer_put_ldr_reg_address(writer, ARM_REG_PC, enter_thunk_ptr);

    code_slice =
        ZzNewCodeSlice(self->allocator, writer->size); // @common-function

    if (!ZzMemoryPatchCode((zaddr)code_slice->data, temp_codeslice_data,
                           writer->size))
        return ZZ_FAILED;

    entry->on_leave_trampoline = code_slice->data;

    return ZZ_DONE;
}