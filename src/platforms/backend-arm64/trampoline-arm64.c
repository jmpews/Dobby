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

#include "interceptor-arm64.h"

#define ZZ_ARM64_TINY_REDIRECT_SIZE 4
#define ZZ_ARM64_FULL_REDIRECT_SIZE 16

ZzInterceptorBackend *ZzBuildInteceptorBackend(ZzAllocator *allocator) {
    ZzInterceptorBackend *backend = (ZzInterceptorBackend *)malloc(sizeof(ZzInterceptorBackend));
    backend->allocator = allocator;

    zz_arm64_writer_init(&backend->arm64_writer, NULL);
    zz_arm64_relocator_init(&backend->arm64_relocator, NULL, &backend->arm64_writer);

    backend->enter_thunk = NULL;
    backend->half_thunk = NULL;
    backend->leave_thunk = NULL;

    ZzThunkerBuildThunk(backend);
    return backend;
}

ZZSTATUS ZzPrepareTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zpointer target_addr = entry->target_ptr;
    zuint redirect_limit;

    ZzArm64HookFunctionEntryBackend *entry_backend;
    entry_backend =
        (ZzArm64HookFunctionEntryBackend *)malloc(sizeof(ZzArm64HookFunctionEntryBackend));
    entry->backend = (struct _ZzHookFunctionEntryBackend *)entry_backend;

    if (entry->try_near_jump) {
        entry_backend->redirect_code_size = ZZ_ARM64_TINY_REDIRECT_SIZE;
    } else {
        zz_arm64_relocator_try_relocate(target_addr, ZZ_ARM64_FULL_REDIRECT_SIZE, &redirect_limit);
        entry_backend->redirect_code_size = ZZ_ARM64_FULL_REDIRECT_SIZE;
    }

    zz_arm64_relocator_init(&self->arm64_relocator, target_addr, &self->arm64_writer);
    return ZZ_SUCCESS;
}

__attribute__((__naked__)) void on_enter_trampoline_template() {
    __asm__ volatile(
        /* store entry address and reserve space for next hop */
        "sub sp, sp, 0x10\n"
        "ldr x17, #0x8\n"
        "b #0xc\n"
        /* entry address */
        ".long 0x0\n"
        ".long 0x0\n"
        "str x17, [sp]\n"
        "ldr x17, #0x8\n"
        "br x17\n"
        /* enter_thunk address */
        ".long 0x0\n"
        ".long 0x0");
}

__attribute__((__naked__)) void on_inovke_trampoline_template() {
    __asm__ volatile(
        /* fixed instruction */
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "ldr x17, #8\n"
        "br x17\n"
        /* rest of orgin function address */
        ".long 0x0\n"
        ".long 0x0");
}

__attribute__((__naked__)) void on_leave_trampoline_template() {
    __asm__ volatile(
        /* store entry address and reserve space for next hop */
        "sub sp, sp, 0x10\n"
        "ldr x17, #0x8\n"
        "b #0xc\n"
        /* entry address */
        ".long 0x0\n"
        ".long 0x0\n"
        "str x17, [sp]\n"
        "ldr x17, #0x8\n"
        "br x17\n"
        /* leave_thunk address */
        ".long 0x0\n"
        ".long 0x0");
}

ZZSTATUS ZzBuildEnterTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzArm64Writer *arm64_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZzArm64HookFunctionEntryBackend *entry_backend =
        (ZzArm64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    zpointer target_addr = entry->target_ptr;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);

    code_slice = NULL;
    do {
        /* 2 stack space: 1. next_hop 2. entry arg */
        zz_arm64_writer_put_sub_reg_reg_imm(arm64_writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 0x8);

        zz_arm64_writer_put_ldr_b_reg_address(arm64_writer, ARM64_REG_X17, (zaddr)entry);
        zz_arm64_writer_put_str_reg_reg_offset(arm64_writer, ARM64_REG_X17, ARM64_REG_SP, 0x0);

        /* jump to enter thunk */
        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                               (zaddr)self->enter_thunk);

        if (code_slice) {
            if (!ZzMemoryPatchCode((zaddr)code_slice->data, arm64_writer->base, arm64_writer->size))
                return ZZ_FAILED;
            break;
        }
        if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
            code_slice =
                ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                                   zz_arm64_writer_near_jump_range_size(), arm64_writer->size);
            if (!code_slice)
                return ZZ_FAILED;
        }
        if (!code_slice)
            code_slice = ZzNewCodeSlice(self->allocator, arm64_writer->size + 4);
        if (!code_slice) {
#if defined(DEBUG_MODE)
            debug_break();
#endif
            return ZZ_FAILED;
        } else {
            zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);
            arm64_writer->pc = code_slice->data;
        }
    } while (code_slice);

    entry->on_enter_trampoline = code_slice->data;

    return status;
}

ZZSTATUS ZzBuildInvokeTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzCodeSlice *code_slice = NULL;
    ZzArm64HookFunctionEntryBackend *entry_backend =
        (ZzArm64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    zpointer target_addr = entry->target_ptr;

    ZzArm64Relocator *arm64_relocator;
    ZzArm64Writer *arm64_writer;
    arm64_relocator = &self->arm64_relocator;
    arm64_writer = &self->arm64_writer;

    zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);

    code_slice = NULL;
    do {
        zz_arm64_relocator_reset(arm64_relocator, target_addr, arm64_writer);
        zsize tmp_relocator_insn_size = 0;
        entry->target_half_ret_addr = 0;

        if (entry->hook_type == HOOK_FUNCTION_TYPE) {
            do {
                zz_arm64_relocator_read_one(arm64_relocator, NULL);
                tmp_relocator_insn_size = arm64_relocator->input_cur - arm64_relocator->input_start;
            } while (tmp_relocator_insn_size < entry_backend->redirect_code_size);
            zz_arm64_relocator_write_all(arm64_relocator);
        } else if (entry->hook_type == HOOK_ADDRESS_TYPE) {
            do {
                zz_arm64_relocator_read_one(arm64_relocator, NULL);
                zz_arm64_relocator_write_one(arm64_relocator);
                tmp_relocator_insn_size = arm64_relocator->input_cur - arm64_relocator->input_start;
                if (arm64_relocator->input_cur >= entry->target_end_ptr &&
                    !entry->target_half_ret_addr) {
                    /* jump to rest target address */
                    zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                                           (zaddr)entry->on_half_trampoline);

                    entry->target_half_ret_addr = (zpointer)arm64_writer->size;
                }
            } while (tmp_relocator_insn_size < entry_backend->redirect_code_size ||
                     arm64_relocator->input_cur < entry->target_end_ptr);
        }

        zpointer restore_target_addr = (zpointer)((zaddr)target_addr + tmp_relocator_insn_size);

        /* jump to rest target address */
        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                               (zaddr)restore_target_addr);

        if (code_slice) {
            if (!ZzMemoryPatchCode((zaddr)code_slice->data, arm64_writer->base, arm64_writer->size))
                return ZZ_FAILED;
            break;
        }
        code_slice = ZzNewCodeSlice(self->allocator, arm64_writer->size + 4);
        if (!code_slice) {
#if defined(DEBUG_MODE)
            debug_break();
#endif
            return ZZ_FAILED;
        } else {
            zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);
            arm64_writer->pc = code_slice->data;
        }
    } while (code_slice);

    if (entry->hook_type == HOOK_ADDRESS_TYPE) {
        // update target_half_ret_addr
        entry->target_half_ret_addr += (zaddr)code_slice->data;
    }
    entry->on_invoke_trampoline = code_slice->data;
    return status;
}

ZZSTATUS ZzBuildHalfTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzArm64Writer *arm64_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZzArm64HookFunctionEntryBackend *entry_backend =
        (ZzArm64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    zpointer target_addr = entry->target_ptr;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);

    code_slice = NULL;
    do {
        /* 2 stack space: 1. next_hop 2. entry arg */
        zz_arm64_writer_put_sub_reg_reg_imm(arm64_writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 0x8);

        zz_arm64_writer_put_ldr_b_reg_address(arm64_writer, ARM64_REG_X17, (zaddr)entry);
        zz_arm64_writer_put_str_reg_reg_offset(arm64_writer, ARM64_REG_X17, ARM64_REG_SP, 0x0);

        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                               (zaddr)self->half_thunk);

        if (code_slice) {
            if (!ZzMemoryPatchCode((zaddr)code_slice->data, arm64_writer->base, arm64_writer->size))
                return ZZ_FAILED;
            break;
        }
        if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
            code_slice =
                ZzNewNearCodeSlice(self->allocator, (zaddr)entry->target_ptr,
                                   zz_arm64_writer_near_jump_range_size(), arm64_writer->size);
            if (!code_slice)
                return ZZ_FAILED;
        }
        if (!code_slice)
            code_slice = ZzNewCodeSlice(self->allocator, arm64_writer->size + 4);
        if (!code_slice) {
#if defined(DEBUG_MODE)
            debug_break();
#endif
            return ZZ_FAILED;
        } else {
            zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);
            arm64_writer->pc = code_slice->data;
        }
    } while (code_slice);

    /* set arm64 on_half_trampoline */
    entry->on_half_trampoline = code_slice->data;

    return status;
}

ZZSTATUS ZzBuildLeaveTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzCodeSlice *code_slice = NULL;
    ZzArm64HookFunctionEntryBackend *entry_backend =
        (ZzArm64HookFunctionEntryBackend *)entry->backend;
    zpointer target_addr = entry->target_ptr;
    ZzArm64Writer *arm64_writer;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);

    do {
        /* 2 stack space: 1. next_hop 2. entry arg */
        zz_arm64_writer_put_sub_reg_reg_imm(arm64_writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 0x8);

        zz_arm64_writer_put_ldr_b_reg_address(arm64_writer, ARM64_REG_X17, (zaddr)entry);
        zz_arm64_writer_put_str_reg_reg_offset(arm64_writer, ARM64_REG_X17, ARM64_REG_SP, 0x0);

        /* jump to leave thunk */
        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                               (zaddr)self->leave_thunk);
        if (code_slice) {
            if (!ZzMemoryPatchCode((zaddr)code_slice->data, arm64_writer->base, arm64_writer->size))
                return ZZ_FAILED;
            break;
        }
        code_slice = ZzNewCodeSlice(self->allocator, arm64_writer->size + 4);
        if (!code_slice) {
#if defined(DEBUG_MODE)
            debug_break();
#endif
            return ZZ_FAILED;
        } else {
            zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);
            arm64_writer->pc = code_slice->data;
        }
    } while (code_slice);

    /* set arm64 on_leave_trampoline */
    entry->on_leave_trampoline = code_slice->data;

    return ZZ_DONE;
}

ZZSTATUS ZzActivateTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    zbyte temp_code_slice_data[256] = {0};
    ZzCodeSlice *code_slice = NULL;
    ZzArm64HookFunctionEntryBackend *entry_backend =
        (ZzArm64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    zpointer target_addr = entry->target_ptr;
    ZzArm64Writer *arm64_writer;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);
    arm64_writer->pc = target_addr;

    if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
        zz_arm64_writer_put_b_imm(arm64_writer,
                                  (zaddr)target_addr - (zaddr)entry->on_enter_trampoline);
    } else {
        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                               (zaddr)entry->on_enter_trampoline);
    }

    if (!ZzMemoryPatchCode((zaddr)target_addr, arm64_writer->base, arm64_writer->size))
        status = ZZ_FAILED;

    return status;
}