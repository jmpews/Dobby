/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "interceptor-arm.h"

#define INSTRUCTION_IS_THUMB(insn_addr) ((insn_addr & 0x1) == 0x1)

#define ZZ_THUMB_TINY_REDIRECT_SIZE 4
#define ZZ_THUMB_FULL_REDIRECT_SIZE 8
#define ZZ_ARM_TINY_REDIRECT_SIZE 4
#define ZZ_ARM_FULL_REDIRECT_SIZE 8

ZzInterceptorBackend *ZzBuildInteceptorBackend(ZzAllocator *allocator) {
    ZzInterceptorBackend *backend = (ZzInterceptorBackend *)malloc(sizeof(ZzInterceptorBackend));
    backend->allocator = allocator;

    zz_arm_writer_init(&backend->arm_writer, NULL);
    zz_arm_relocator_init(&backend->arm_relocator, NULL, &backend->arm_writer);

    zz_thumb_writer_init(&backend->thumb_writer, NULL);
    zz_thumb_relocator_init(&backend->thumb_relocator, NULL, &backend->thumb_writer);
    ZzThunkerBuildThunk(backend);
    return backend;
}

// 1. confirm enter trampoline jump type. `abs jump` or `near jump`
// 2. confirm relocator need length
ZZSTATUS ZzPrepareTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbool is_thumb = FALSE;
    zpointer target_addr = entry->target_ptr;
    zuint redirect_limit;

    ZzArmHookFunctionEntryBackend *entry_backend;
    entry_backend = (ZzArmHookFunctionEntryBackend *)malloc(sizeof(ZzArmHookFunctionEntryBackend));
    entry->backend = (struct _ZzHookFunctionEntryBackend *)entry_backend;

    is_thumb = INSTRUCTION_IS_THUMB((zaddr)target_addr);

    if (is_thumb) {
        if (entry->try_near_jump) {
            entry_backend->redirect_code_size = ZZ_THUMB_TINY_REDIRECT_SIZE;
        } else {
            zz_thumb_relocator_try_relocate(target_addr, ZZ_THUMB_FULL_REDIRECT_SIZE,
                                            &redirect_limit);
            entry_backend->redirect_code_size = ZZ_THUMB_FULL_REDIRECT_SIZE;
            if ((zaddr)target_addr % 4) {
                entry_backend->redirect_code_size += 2;
            }
        }
    } else {
        if (entry->try_near_jump) {
            entry_backend->redirect_code_size = ZZ_ARM_FULL_REDIRECT_SIZE;
        } else {
            zz_arm_relocator_try_relocate(target_addr, ZZ_ARM_FULL_REDIRECT_SIZE, &redirect_limit);
            entry_backend->redirect_code_size = ZZ_ARM_FULL_REDIRECT_SIZE;
        }
    }

    zz_arm_relocator_init(&self->arm_relocator, target_addr, &self->arm_writer);
    zz_thumb_relocator_init(&self->thumb_relocator, target_addr, &self->thumb_writer);
    return ZZ_SUCCESS;
}

ZZSTATUS ZzBuildEnterTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzArmWriter *arm_writer = NULL;
    ZzArmWriter *thumb_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZzArmHookFunctionEntryBackend *entry_backend = (ZzArmHookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status;
    zbool is_thumb;
    zpointer target_addr = entry->target_ptr;

    thumb_writer = &self->thumb_writer;
    zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);

    is_thumb = INSTRUCTION_IS_THUMB((zaddr)target_addr);

    code_slice = NULL;
    do {
        /* 2 stack space: 1. next_hop 2. entry arg */
        zz_thumb_writer_put_sub_reg_imm(thumb_writer, ARM_REG_SP, 0xc);
        /* push r7 */
        zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x0);

        zz_thumb_writer_put_ldr_b_reg_address(thumb_writer, ARM_REG_R1, (zaddr)entry);
        zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x4);

        /* pop r7 */
        zz_thumb_writer_put_ldr_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x0);
        zz_thumb_writer_put_add_reg_imm(thumb_writer, ARM_REG_SP, 0x4);

        zz_thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC, (zaddr)self->enter_thunk);

        if (code_slice) {
            if (!ZzMemoryPatchCode((zaddr)code_slice->data, thumb_writer->base, thumb_writer->size))
                return ZZ_FAILED;
            break;
        }
        if (is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {

            code_slice =
                ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                                   zz_thumb_writer_near_jump_range_size(), thumb_writer->size);
            if (!code_slice)
                return ZZ_FAILED;
        }

        if (!is_thumb && entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE) {
            code_slice =
                ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                                   zz_arm_writer_near_jump_range_size(), thumb_writer->size);
            if (!code_slice)
                return ZZ_FAILED;
        }

        if (entry_backend->redirect_code_size != ZZ_ARM_TINY_REDIRECT_SIZE &&
            entry_backend->redirect_code_size != ZZ_THUMB_TINY_REDIRECT_SIZE)
            code_slice = ZzNewCodeSlice(self->allocator, thumb_writer->size + 4);

        if (!code_slice) {
#if defined(DEBUG_MODE)
            debug_break();
#endif
            return ZZ_FAILED;
        } else {
            zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);
            thumb_writer->pc = code_slice->data;
        }
    } while (code_slice);
    entry->on_enter_trampoline = code_slice->data + 1;
    status = ZZ_SUCCESS;

    return status;
}

ZZSTATUS ZzBuildInvokeTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzCodeSlice *code_slice = NULL;

    ZzArmHookFunctionEntryBackend *entry_backend = (ZzArmHookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status;
    zbool is_thumb;
    zpointer target_addr = entry->target_ptr;
    zpointer target_end_addr;

    is_thumb = INSTRUCTION_IS_THUMB((zaddr)target_addr);

    if (is_thumb) {
        target_addr = (zpointer)((zaddr)target_addr & ~(zaddr)1);
        target_end_addr = (zpointer)((zaddr)entry->target_end_ptr & ~(zaddr)1);
    }

    if (is_thumb) {
        ZzThumbRelocator *thumb_relocator;
        ZzThumbWriter *thumb_writer;
        thumb_relocator = &self->thumb_relocator;
        thumb_writer = &self->thumb_writer;

        zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);
        code_slice = NULL;

        do {
            zz_thumb_relocator_reset(thumb_relocator, target_addr, thumb_writer);
            zsize tmp_relocator_insn_size = 0;
            entry->target_half_ret_addr = 0;

            if (entry->hook_type == HOOK_FUNCTION_TYPE) {
                do {
                    zz_thumb_relocator_read_one(thumb_relocator, NULL);
                    tmp_relocator_insn_size =
                        thumb_relocator->input_cur - thumb_relocator->input_start;
                } while (tmp_relocator_insn_size < entry_backend->redirect_code_size);
                zz_thumb_relocator_write_all(thumb_relocator);
            } else if (entry->hook_type == HOOK_ADDRESS_TYPE) {
                do {
                    zz_thumb_relocator_read_one(thumb_relocator, NULL);
                    zz_thumb_relocator_write_one(thumb_relocator);
                    tmp_relocator_insn_size =
                        thumb_relocator->input_cur - thumb_relocator->input_start;
                    if (thumb_relocator->input_cur >= target_end_addr &&
                        !entry->target_half_ret_addr) {
                        /* jump to rest target address */
                        zz_thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC,
                                                            (zaddr)entry->on_half_trampoline);

                        entry->target_half_ret_addr = (zpointer)(thumb_writer->size + 1);
                    }
                } while (tmp_relocator_insn_size < entry_backend->redirect_code_size ||
                         thumb_relocator->input_cur < target_end_addr);
            }

            zpointer restore_target_addr = (zpointer)((zaddr)target_addr + tmp_relocator_insn_size);

            /* jump to rest target address */
            zz_thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC,
                                                (zaddr)(restore_target_addr + 1));

            if (code_slice) {
                if (!ZzMemoryPatchCode((zaddr)code_slice->data, thumb_writer->base,
                                       thumb_writer->size))
                    return ZZ_FAILED;
                break;
            }
            code_slice = ZzNewCodeSlice(self->allocator, thumb_writer->size + 4);
            if (!code_slice) {
#if defined(DEBUG_MODE)
                debug_break();
#endif
                return ZZ_FAILED;
            } else {
                zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);
                thumb_writer->pc = code_slice->data;
            }
        } while (code_slice);
        entry->on_invoke_trampoline = code_slice->data + 1;
    } else {

        ZzArmRelocator *arm_relocator;
        ZzArmWriter *arm_writer;
        arm_relocator = &self->arm_relocator;
        arm_writer = &self->arm_writer;

        zz_arm_writer_reset(arm_writer, temp_code_slice_data);
        code_slice = NULL;

        do {
            zz_arm_relocator_reset(arm_relocator, target_addr, arm_writer);
            entry->target_half_ret_addr = 0;
            zsize tmp_relocator_insn_size = 0;

            if (entry->hook_type == HOOK_FUNCTION_TYPE) {
                do {
                    zz_arm_relocator_read_one(arm_relocator, NULL);
                    tmp_relocator_insn_size = arm_relocator->input_cur - arm_relocator->input_start;
                } while (tmp_relocator_insn_size < entry_backend->redirect_code_size);
                zz_arm_relocator_write_all(arm_relocator);
            } else if (entry->hook_type == HOOK_ADDRESS_TYPE) {
                do {
                    zz_arm_relocator_read_one(arm_relocator, NULL);
                    zz_arm_relocator_write_one(arm_relocator);
                    tmp_relocator_insn_size = arm_relocator->input_cur - arm_relocator->input_start;
                    if (arm_relocator->input_cur >= target_end_addr &&
                        !entry->target_half_ret_addr) {
                        /* jump to rest target address */
                        zz_arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC,
                                                          (zaddr)entry->on_half_trampoline);

                        entry->target_half_ret_addr = (zpointer)arm_writer->size;
                    }
                } while (tmp_relocator_insn_size < entry_backend->redirect_code_size ||
                         arm_relocator->input_cur < target_end_addr);
            }

            zpointer restore_target_addr = (zpointer)((zaddr)target_addr + tmp_relocator_insn_size);

            /* jump to rest target address */
            zz_arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC, (zaddr)restore_target_addr);

            if (code_slice) {
                if (!ZzMemoryPatchCode((zaddr)code_slice->data, arm_writer->base, arm_writer->size))
                    return ZZ_FAILED;
                break;
            }
            code_slice = ZzNewCodeSlice(self->allocator, arm_writer->size + 4);
            if (!code_slice) {
#if defined(DEBUG_MODE)
                debug_break();
#endif
                return ZZ_FAILED;
            } else {
                zz_arm_writer_reset(arm_writer, temp_code_slice_data);
                arm_writer->pc = code_slice->data;
            }

        } while (code_slice);
        entry->on_invoke_trampoline = code_slice->data;
    }

    if (entry->hook_type == HOOK_ADDRESS_TYPE) {

        entry->target_half_ret_addr += (zaddr)code_slice->data;
    }

    return status;
}

ZZSTATUS ZzBuildHalfTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzArmWriter *arm_writer = NULL;
    ZzArmWriter *thumb_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZzArmHookFunctionEntryBackend *entry_backend = (ZzArmHookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status;
    zbool is_thumb;
    zpointer target_addr = entry->target_ptr;

    thumb_writer = &self->thumb_writer;
    zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);

    is_thumb = INSTRUCTION_IS_THUMB((zaddr)target_addr);

    code_slice = NULL;
    do {
        /* 2 stack space: 1. next_hop 2. entry arg */
        zz_thumb_writer_put_sub_reg_imm(thumb_writer, ARM_REG_SP, 0xc);
        /* push r7 */
        zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x0);

        zz_thumb_writer_put_ldr_b_reg_address(thumb_writer, ARM_REG_R1, (zaddr)entry);
        zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x4);

        /* pop r7 */
        zz_thumb_writer_put_ldr_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x0);
        zz_thumb_writer_put_add_reg_imm(thumb_writer, ARM_REG_SP, 0x4);

        zz_thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC, (zaddr)self->half_thunk);

        if (code_slice) {
            if (!ZzMemoryPatchCode((zaddr)code_slice->data, thumb_writer->base, thumb_writer->size))
                return ZZ_FAILED;
            break;
        }
        if (is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {

            code_slice =
                ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                                   zz_thumb_writer_near_jump_range_size(), thumb_writer->size);
            if (!code_slice)
                return ZZ_FAILED;
        }

        if (!is_thumb && entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE) {
            code_slice =
                ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                                   zz_arm_writer_near_jump_range_size(), thumb_writer->size);
            if (!code_slice)
                return ZZ_FAILED;
        }

        if (entry_backend->redirect_code_size != ZZ_ARM_TINY_REDIRECT_SIZE &&
            entry_backend->redirect_code_size != ZZ_THUMB_TINY_REDIRECT_SIZE)
            code_slice = ZzNewCodeSlice(self->allocator, thumb_writer->size + 4);

        if (!code_slice) {
#if defined(DEBUG_MODE)
            debug_break();
#endif
            return ZZ_FAILED;
        } else {
            zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);
            thumb_writer->pc = code_slice->data;
        }
    } while (code_slice);
    entry->on_half_trampoline = code_slice->data + 1;
    status = ZZ_SUCCESS;

    return status;
}

ZZSTATUS ZzBuildLeaveTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzCodeSlice *code_slice = NULL;
    ZZSTATUS status;
    zbool is_thumb;
    ZzArmWriter *thumb_writer;

    ZzArmHookFunctionEntryBackend *entry_backend = (ZzArmHookFunctionEntryBackend *)entry->backend;

    zpointer target_addr = entry->target_ptr;
    thumb_writer = &self->thumb_writer;
    zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);

    is_thumb = INSTRUCTION_IS_THUMB((zaddr)target_addr);

    code_slice = NULL;
    do {
        /* 2 stack space: 1. next_hop 2. entry arg */
        zz_thumb_writer_put_sub_reg_imm(thumb_writer, ARM_REG_SP, 0xc);
        /* push r7 */
        zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x0);

        zz_thumb_writer_put_ldr_b_reg_address(thumb_writer, ARM_REG_R1, (zaddr)entry);
        zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x4);

        /* pop r7 */
        zz_thumb_writer_put_ldr_reg_reg_offset(thumb_writer, ARM_REG_R1, ARM_REG_SP, 0x0);
        zz_thumb_writer_put_add_reg_imm(thumb_writer, ARM_REG_SP, 0x4);

        zz_thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC, (zaddr)self->leave_thunk);

        if (code_slice) {

            if (!ZzMemoryPatchCode((zaddr)code_slice->data, thumb_writer->base, thumb_writer->size))
                return ZZ_FAILED;
            break;
        }
        code_slice = ZzNewCodeSlice(self->allocator, thumb_writer->size + 4);
        if (!code_slice) {
#if defined(DEBUG_MODE)
            debug_break();
#endif
            return ZZ_FAILED;
        } else {
            zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);
            thumb_writer->pc = code_slice->data;
        }
    } while (code_slice);

    entry->on_leave_trampoline = code_slice->data + 1;

    return ZZ_DONE;
}

ZZSTATUS ZzActiveTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzCodeSlice *code_slice = 0;

    ZzArmHookFunctionEntryBackend *entry_backend = (ZzArmHookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status;
    zbool is_thumb;
    zpointer target_addr = entry->target_ptr;

    is_thumb = INSTRUCTION_IS_THUMB((zaddr)target_addr);

    if (is_thumb) {
        target_addr = (zpointer)((zaddr)target_addr & ~(zaddr)1);

        ZzThumbWriter *thumb_writer;
        thumb_writer = &self->thumb_writer;
        zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);
        thumb_writer->pc = target_addr;

        if (entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
            zz_thumb_writer_put_b_imm(thumb_writer,
                                      (zaddr)target_addr - (zaddr)entry->on_enter_trampoline);
        } else {
            zz_thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC,
                                                (zaddr)entry->on_enter_trampoline);
        }
        if (!ZzMemoryPatchCode((zaddr)target_addr, thumb_writer->base, thumb_writer->size))
            return ZZ_FAILED;
    } else {
        ZzArmWriter *arm_writer;
        arm_writer = &self->arm_writer;
        zz_arm_writer_reset(arm_writer, temp_code_slice_data);
        arm_writer->pc = target_addr;

        if (entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE) {
            zz_arm_writer_put_b_imm(arm_writer,
                                    (zaddr)target_addr - (zaddr)entry->on_enter_trampoline);
        } else {
            zz_arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC,
                                              (zaddr)entry->on_enter_trampoline);
        }
        if (!ZzMemoryPatchCode((zaddr)target_addr, arm_writer->base, arm_writer->size))
            return ZZ_FAILED;
    }

    return ZZ_DONE_HOOK;
}
