#include "interceptor-arm.h"
#include "backend-arm-helper.h"
#include <stdlib.h>

#define ZZ_THUMB_TINY_REDIRECT_SIZE 4
#define ZZ_THUMB_FULL_REDIRECT_SIZE 8
#define ZZ_ARM_TINY_REDIRECT_SIZE 4
#define ZZ_ARM_FULL_REDIRECT_SIZE 8

ZzInterceptorBackend *ZzBuildInteceptorBackend(ZzAllocator *allocator) {
    if (!ZzMemoryIsSupportAllocateRXPage()) {
        ZZ_DEBUG_LOG_STR("memory is not support allocate r-x Page!");
        return NULL;
    }

    ZZSTATUS status;
    ZzInterceptorBackend *backend = (ZzInterceptorBackend *) zz_malloc_with_zero(
            sizeof(ZzInterceptorBackend));

    zz_arm_writer_init(&backend->arm_writer, NULL, 0);
    zz_arm_reader_init(&backend->arm_reader, NULL);
    zz_arm_relocator_init(&backend->arm_relocator, &backend->arm_reader, &backend->arm_writer);

    zz_thumb_writer_init(&backend->thumb_writer, NULL, 0);
    zz_thumb_reader_init(&backend->thumb_reader, NULL);
    zz_thumb_relocator_init(&backend->thumb_relocator, &backend->thumb_reader,
                            &backend->thumb_writer);

    backend->allocator = allocator;
    backend->enter_thunk = NULL;
    backend->insn_leave_thunk = NULL;
    backend->leave_thunk = NULL;
    backend->dynamic_binary_instrumentation_thunk = NULL;

    // build enter/leave/inovke thunk
    status = ZzThunkerBuildThunk(backend);

    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= Global Interceptor Info ======= \n");
        sprintf(buffer + strlen(buffer), "\t\tenter_thunk: %p\n", backend->enter_thunk);
        sprintf(buffer + strlen(buffer), "\t\tleave_thunk: %p\n", backend->leave_thunk);
        sprintf(buffer + strlen(buffer), "\t\tinsn_leave_thunk: %p\n", backend->insn_leave_thunk);
        sprintf(buffer + strlen(buffer), "\t\tdynamic_binary_instrumentation_thunk: %p\n", backend->dynamic_binary_instrumentation_thunk);
        HookZzDebugInfoLog("%s", buffer);
    }

    if (status == ZZ_FAILED) {
        HookZzDebugInfoLog("%s", "ZzThunkerBuildThunk return ZZ_FAILED\n");
        return NULL;
    }

    return backend;
}

ZZSTATUS ZzFreeTrampoline(ZzHookFunctionEntry *entry) {
    if (entry->on_invoke_trampoline) {
        //TODO
    }

    if (entry->on_enter_trampoline) {
        //TODO
    }

    if (entry->on_enter_transfer_trampoline) {
        //TODO
    }

    if (entry->on_leave_trampoline) {
        //TODO
    }

    if (entry->on_invoke_trampoline) {
        //TODO
    }
    return ZZ_SUCCESS;
}

ZZSTATUS ZzPrepareTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    bool is_thumb = FALSE;
    zz_addr_t target_addr = (zz_addr_t) entry->target_ptr;
    zz_size_t redirect_limit = 0;
    ZzARMHookFunctionEntryBackend *entry_backend;

    entry_backend = (ZzARMHookFunctionEntryBackend *) zz_malloc_with_zero(
            sizeof(ZzARMHookFunctionEntryBackend));
    entry->backend = (struct _ZzHookFunctionEntryBackend *) entry_backend;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t) entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t) entry->target_ptr & ~(zz_addr_t) 1;

    if (is_thumb) {
        if (entry->try_near_jump) {
            entry_backend->redirect_code_size = ZZ_THUMB_TINY_REDIRECT_SIZE;
        } else {
            // check the first few instructions, preparatory work of instruction-fixing
            zz_thumb_relocator_try_relocate((zz_ptr_t) target_addr, ZZ_THUMB_FULL_REDIRECT_SIZE,
                                            &redirect_limit);
            if (redirect_limit != 0 && redirect_limit > ZZ_THUMB_TINY_REDIRECT_SIZE &&
                redirect_limit < ZZ_THUMB_FULL_REDIRECT_SIZE) {
                entry->try_near_jump = TRUE;
                entry_backend->redirect_code_size = ZZ_THUMB_TINY_REDIRECT_SIZE;
            } else if (redirect_limit != 0 && redirect_limit < ZZ_THUMB_TINY_REDIRECT_SIZE) {
                return ZZ_FAILED;
            } else {
                // put nop to align !!!!
                entry_backend->redirect_code_size = ZZ_THUMB_FULL_REDIRECT_SIZE;
                if (target_addr % 4) {
                    entry_backend->redirect_code_size += 2;
                }
            }
        }
        self->thumb_relocator.try_relocated_length = entry_backend->redirect_code_size;
    } else {
        if (entry->try_near_jump) {
            entry_backend->redirect_code_size = ZZ_ARM_TINY_REDIRECT_SIZE;
        } else {
            // check the first few instructions, preparatory work of instruction-fixing
            zz_arm_relocator_try_relocate((zz_ptr_t) target_addr, ZZ_ARM_FULL_REDIRECT_SIZE,
                                          &redirect_limit);
            if (redirect_limit != 0 && redirect_limit > ZZ_ARM_TINY_REDIRECT_SIZE &&
                redirect_limit < ZZ_ARM_FULL_REDIRECT_SIZE) {
                entry->try_near_jump = TRUE;
                entry_backend->redirect_code_size = ZZ_ARM_TINY_REDIRECT_SIZE;
            } else if (redirect_limit != 0 && redirect_limit < ZZ_ARM_TINY_REDIRECT_SIZE) {
                return ZZ_FAILED;
            } else {
                entry_backend->redirect_code_size = ZZ_ARM_FULL_REDIRECT_SIZE;
            }
        }
        self->arm_relocator.try_relocated_length = entry_backend->redirect_code_size;
    }

    // save original prologue
    memcpy(entry->origin_prologue.data, (zz_ptr_t) target_addr, entry_backend->redirect_code_size);
    entry->origin_prologue.size = entry_backend->redirect_code_size;
    entry->origin_prologue.address = (zz_ptr_t) target_addr;

    // relocator initialize
    zz_arm_relocator_init(&self->arm_relocator, &self->arm_reader, &self->arm_writer);
    zz_thumb_relocator_init(&self->thumb_relocator, &self->thumb_reader, &self->thumb_writer);
    return ZZ_SUCCESS;
}

ZZSTATUS ZzBuildEnterTransferTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256] = {0};
    ZzARMAssemblerWriter *arm_writer = NULL;
    ZzARMAssemblerWriter *thumb_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZzARMHookFunctionEntryBackend *entry_backend = (ZzARMHookFunctionEntryBackend *) entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    bool is_thumb = TRUE;
    zz_addr_t target_addr = (zz_addr_t) entry->target_ptr;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t) entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t) entry->target_ptr & ~(zz_addr_t) 1;

    if (is_thumb) {
        thumb_writer = &self->thumb_writer;
        zz_thumb_writer_reset(thumb_writer, temp_code_slice, (zz_addr_t) temp_code_slice);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC,
                                                (zz_addr_t) entry->replace_call);
        } else if(entry->hook_type == HOOK_TYPE_DBI) {
            zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC,
                                                (zz_addr_t) entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC,
                                                (zz_addr_t) entry->on_enter_trampoline);
        }
        if ((is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) ||
            (!is_thumb && entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE)) {
            code_slice =
                    zz_thumb_code_patch(thumb_writer, self->allocator, target_addr,
                                        zz_thumb_writer_near_jump_range_size()-0x10);
        } else {
            code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
        }

        if (code_slice)
            entry->on_enter_transfer_trampoline = code_slice->data + 1;
        else
            return ZZ_FAILED;
    } else {
        arm_writer = &self->arm_writer;
        zz_arm_writer_reset(arm_writer, temp_code_slice, 0);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            zz_arm_writer_put_ldr_reg_address(arm_writer, ZZ_ARM_REG_PC,
                                              (zz_addr_t) entry->replace_call);
        } else if(entry->hook_type == HOOK_TYPE_DBI) {
            zz_arm_writer_put_ldr_reg_address(arm_writer, ZZ_ARM_REG_PC,
                                              (zz_addr_t) entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            zz_arm_writer_put_ldr_reg_address(arm_writer, ZZ_ARM_REG_PC,
                                              (zz_addr_t) entry->on_enter_trampoline);
        }

        if ((is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) ||
            (!is_thumb && entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE)) {
            code_slice = zz_arm_code_patch(arm_writer, self->allocator, target_addr, zz_arm_writer_near_jump_range_size()-0x10);
        } else {
            code_slice = zz_arm_code_patch(arm_writer, self->allocator, 0, 0);
        }
        if (code_slice)
            entry->on_enter_transfer_trampoline = code_slice->data;
        else
            return ZZ_FAILED;
    }

    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= EnterTransferTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\ton_enter_transfer_trampoline: %p\n", entry->on_enter_transfer_trampoline);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        sprintf(buffer + strlen(buffer), "\t\thook_entry: %p\n", (void *) entry);
        if(entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            sprintf(buffer + strlen(buffer), "\t\tjump_target: replace_call(%p)\n", (void *)entry->replace_call);
        } else if (entry->hook_type == HOOK_TYPE_DBI) {
            sprintf(buffer + strlen(buffer), "\t\tjump_target: on_dynamic_binary_instrumentation_trampoline(%p)\n", (void *)entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            sprintf(buffer + strlen(buffer), "\t\tjump_target: on_enter_trampoline(%p)\n", (void *)entry->on_enter_trampoline);
        }
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildEnterTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256] = {0};
    ZzARMAssemblerWriter *arm_writer = NULL;
    ZzARMAssemblerWriter *thumb_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZzARMHookFunctionEntryBackend *entry_backend = (ZzARMHookFunctionEntryBackend *) entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    bool is_thumb;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t) entry->target_ptr);

    thumb_writer = &self->thumb_writer;
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);

    /* prepare 2 stack space: 1. next_hop 2. entry arg */
    zz_thumb_writer_put_sub_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0xc);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // push r7
    zz_thumb_writer_put_ldr_b_reg_address(thumb_writer, ZZ_ARM_REG_R1, (zz_addr_t) entry);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);
    zz_thumb_writer_put_ldr_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // pop r7
    zz_thumb_writer_put_add_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0x4);

    // jump to enter thunk
    zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC, (zz_addr_t) self->enter_thunk);

    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_enter_trampoline = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // build the double trampline aka enter_transfer_trampoline
    if (entry->hook_type != HOOK_TYPE_FUNCTION_via_GOT) {
        if ((is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) ||
            (!is_thumb && entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE)) {
            ZzBuildEnterTransferTrampoline(self, entry);
        }
    }
    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= EnterTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", code_slice->data);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        sprintf(buffer + strlen(buffer), "\t\tjump_target: enter_thunk(%p)\n", (void *) self->enter_thunk);
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildDynamicBinaryInstrumentationTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256] = {0};
    ZzARMAssemblerWriter *arm_writer = NULL;
    ZzARMAssemblerWriter *thumb_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZzARMHookFunctionEntryBackend *entry_backend = (ZzARMHookFunctionEntryBackend *) entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    bool is_thumb;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t) entry->target_ptr);

    thumb_writer = &self->thumb_writer;
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);

    /* prepare 2 stack space: 1. next_hop 2. entry arg */
    zz_thumb_writer_put_sub_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0xc);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // push r7
    zz_thumb_writer_put_ldr_b_reg_address(thumb_writer, ZZ_ARM_REG_R1, (zz_addr_t) entry);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);
    zz_thumb_writer_put_ldr_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // pop r7
    zz_thumb_writer_put_add_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0x4);

    // jump to dynamic_binary_instrumentation_thunk
    zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC, (zz_addr_t) self->dynamic_binary_instrumentation_thunk);

    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_dynamic_binary_instrumentation_trampoline = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // build the double trampline aka enter_transfer_trampoline
    if ((is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) ||
        (!is_thumb && entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE)) {
        ZzBuildEnterTransferTrampoline(self, entry);
    }

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= DynamicBinaryInstrumentationTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\tdynamic_binary_instrumentation_trampoline: %p\n", entry->on_dynamic_binary_instrumentation_trampoline);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        sprintf(buffer + strlen(buffer), "\t\thook_entry: %p\n", (void *) entry);
        sprintf(buffer + strlen(buffer), "\t\tjump_target: dynamic_binary_instrumentation_thunk(%p)\n", (void *) self->dynamic_binary_instrumentation_thunk);
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildInvokeTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256] = {0};
    ZzCodeSlice *code_slice = NULL;
    ZzARMHookFunctionEntryBackend *entry_backend = (ZzARMHookFunctionEntryBackend *) entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    bool is_thumb = TRUE;
    zz_addr_t target_addr = (zz_addr_t) entry->target_ptr;
    zz_ptr_t restore_next_insn_addr;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t) entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t) entry->target_ptr & ~(zz_addr_t) 1;


    if (is_thumb) {
        ZzThumbRelocator *thumb_relocator;
        ZzThumbAssemblerWriter *thumb_writer;
        ZzARMReader *thumb_reader;
        thumb_relocator = &self->thumb_relocator;
        thumb_writer = &self->thumb_writer;
        thumb_reader = &self->thumb_reader;

        zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);
        zz_thumb_reader_reset(thumb_reader, (zz_ptr_t) target_addr);
        zz_thumb_relocator_reset(thumb_relocator, thumb_reader, thumb_writer);

        if (entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
            zz_thumb_relocator_read_one(thumb_relocator, NULL);
            zz_thumb_relocator_write_one(thumb_relocator);

            zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC,
                                                        (zz_addr_t) entry->on_insn_leave_trampoline);
            do {
                zz_thumb_relocator_read_one(thumb_relocator, NULL);
                zz_thumb_relocator_write_one(thumb_relocator);
            } while (thumb_relocator->input->size < entry_backend->redirect_code_size );
        } else {
            do {
                zz_thumb_relocator_read_one(thumb_relocator, NULL);
            } while (thumb_relocator->input->size < entry_backend->redirect_code_size);
            zz_thumb_relocator_write_all(thumb_relocator);
        }

        // jump to rest function instructions address
        restore_next_insn_addr = (zz_ptr_t) ((zz_addr_t) target_addr + thumb_relocator->input->size);
        zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC,
                                            (zz_addr_t) (restore_next_insn_addr + 1));

        // code patch
        code_slice = zz_thumb_relocate_code_patch(thumb_relocator, thumb_writer, self->allocator, 0,
                                                  0);
        if (code_slice)
            entry->on_invoke_trampoline = code_slice->data + 1;
        else
            return ZZ_FAILED;

        if (entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
            ZzARMRelocatorInstruction relocator_insn = thumb_relocator->relocator_insns[1];
            entry->next_insn_addr =
                    (relocator_insn.relocated_insns[0]->pc - thumb_relocator->output->start_pc) + (zz_addr_t) code_slice->data + 1;
        }
    } else {
        ZzARMRelocator *arm_relocator;
        ZzARMAssemblerWriter *arm_writer;
        ZzARMReader *arm_reader;
        arm_relocator = &self->arm_relocator;
        arm_writer = &self->arm_writer;
        arm_reader = &self->arm_reader;

        zz_arm_writer_reset(arm_writer, temp_code_slice, 0);
        zz_arm_reader_reset(arm_reader, (zz_ptr_t) target_addr);
        zz_arm_relocator_reset(arm_relocator, arm_reader, arm_writer);

        if (entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
            zz_arm_relocator_read_one(arm_relocator, NULL);
            zz_arm_relocator_write_one(arm_relocator);

            zz_arm_writer_put_ldr_reg_address(arm_writer, ZZ_ARM_REG_PC,
                                                (zz_addr_t) entry->on_insn_leave_trampoline);
            do {
                zz_arm_relocator_read_one(arm_relocator, NULL);
                zz_arm_relocator_write_one(arm_relocator);
            } while (arm_relocator->input->size < entry_backend->redirect_code_size );
        } else {
            do {
                zz_arm_relocator_read_one(arm_relocator, NULL);
            } while (arm_relocator->input->size < entry_backend->redirect_code_size);
            zz_arm_relocator_write_all(arm_relocator);
        }

        // jump to rest target address
        restore_next_insn_addr = (zz_ptr_t) ((zz_addr_t) target_addr + arm_relocator->input->size);
        zz_arm_writer_put_ldr_reg_address(arm_writer, ZZ_ARM_REG_PC,
                                          (zz_addr_t) restore_next_insn_addr);

        code_slice = zz_arm_relocate_code_patch(arm_relocator, arm_writer, self->allocator, 0, 0);
        if (code_slice)
            entry->on_invoke_trampoline = code_slice->data;
        else
            return ZZ_FAILED;

        //
        if (entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
            ZzARMRelocatorInstruction relocator_insn = arm_relocator->relocator_insns[1];
            entry->next_insn_addr =
                    (relocator_insn.relocated_insns[0]->pc - arm_relocator->output->start_pc) + (zz_addr_t) code_slice->data;
        }
    }

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        char origin_prologue[256] = {0};
        int t = 0;
        sprintf(buffer + strlen(buffer), "======= InvokeTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        sprintf(buffer + strlen(buffer), "\t\tjump_target: restore_next_insn_addr(%p)\n", (void *) restore_next_insn_addr);
        sprintf(buffer + strlen(buffer), "======= InvokeTrampoline Relocator ======= \n");
        if (is_thumb) {
            for (zz_addr_t p = self->thumb_relocator.input->r_start_address;
                 p < self->thumb_relocator.input->r_current_address; p++, t = t + 5) {
                sprintf(origin_prologue + t, "0x%.2x ", *(unsigned char *) p);
            }
            sprintf(buffer + strlen(buffer), "\t\t\tThumb Origin Prologue:: %s\n", origin_prologue);
            sprintf(buffer + strlen(buffer), "\t\tThumb Relocator Input Start Address: %p\n", (zz_ptr_t) self->thumb_relocator.input->r_start_address);
            sprintf(buffer + strlen(buffer), "\t\tThumb Relocator Input Instruction Number: %ld\n", self->thumb_relocator.input->insn_size);
            sprintf(buffer + strlen(buffer), "\t\tThumb Relocator Input Size: %p\n", (zz_ptr_t) self->thumb_relocator.input->size);
            sprintf(buffer + strlen(buffer), "\t\tThumb Relocator Output Start Address: %p\n", code_slice->data);
            sprintf(buffer + strlen(buffer), "\t\tThumb Relocator Output Instruction Number: %p\n", (zz_ptr_t)self->thumb_relocator.input->insn_size);
            sprintf(buffer + strlen(buffer), "\t\tThumb Relocator Output Size: %ld\n", self->thumb_relocator.input->size);
            for(int i = 0; i < self->thumb_relocator.relocator_insn_size; i++) {
                sprintf(buffer + strlen(buffer), "\t\t\torigin input(%p) -> relocated ouput(%p), relocate %ld instruction\n", (zz_ptr_t )self->thumb_relocator.relocator_insns[i].origin_insn->address, (zz_ptr_t )self->thumb_relocator.relocator_insns[i].relocated_insns[0]->address, self->thumb_relocator.relocator_insns[i].relocated_insn_size);
            }
        } else {
            for (zz_addr_t p = self->arm_relocator.input->r_start_address;
                 p < self->arm_relocator.input->r_current_address; p++, t = t + 5) {
                sprintf(origin_prologue + t, "0x%.2x ", *(unsigned char *) p);
            }
            sprintf(buffer + strlen(buffer), "\t\t\tARM Origin Prologue: %s\n", origin_prologue);
            sprintf(buffer + strlen(buffer), "\t\tARM Relocator Input Start Address: %p\n", (zz_ptr_t) self->arm_relocator.input->r_start_address);
            sprintf(buffer + strlen(buffer), "\t\tARM Relocator Input Instruction Number: %ld\n", self->arm_relocator.input->insn_size);
            sprintf(buffer + strlen(buffer), "\t\tARM Relocator Input Size: %p\n", (zz_ptr_t) self->arm_relocator.input->size);
            sprintf(buffer + strlen(buffer), "\t\tARM Relocator Output Start Address: %p\n", code_slice->data);
            sprintf(buffer + strlen(buffer), "\t\tARM Relocator Output Instruction Number: %p\n", (zz_ptr_t)self->arm_relocator.input->insn_size);
            sprintf(buffer + strlen(buffer), "\t\tARM Relocator Output Size: %ld\n", self->arm_relocator.input->size);
            for(int i = 0; i < self->arm_relocator.relocator_insn_size; i++) {
                sprintf(buffer + strlen(buffer), "\t\t\torigin input(%p) -> relocated ouput(%p), relocate %ld instruction\n", (zz_ptr_t )self->arm_relocator.relocator_insns[i].origin_insn->address, (zz_ptr_t )self->arm_relocator.relocator_insns[i].relocated_insns[0]->address, self->arm_relocator.relocator_insns[i].relocated_insn_size);
            }
        }
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildInsnLeaveTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256] = {0};
    ZzARMAssemblerWriter *arm_writer = NULL;
    ZzARMAssemblerWriter *thumb_writer = NULL;
    ZzCodeSlice *code_slice = NULL;
    ZZSTATUS status = ZZ_SUCCESS;

    thumb_writer = &self->thumb_writer;
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);

    // prepare 2 stack space: 1. next_hop 2. entry arg
    zz_thumb_writer_put_sub_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0xc);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // push r7
    zz_thumb_writer_put_ldr_b_reg_address(thumb_writer, ZZ_ARM_REG_R1, (zz_addr_t) entry);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);
    zz_thumb_writer_put_ldr_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // pop r7
    zz_thumb_writer_put_add_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0x4);

    // jump to leave_thunk
    zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC, (zz_addr_t) self->insn_leave_thunk);

    // code patch
    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_insn_leave_trampoline = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= InsnLeaveTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\ton_insn_leave_trampoline: %p\n", entry->on_insn_leave_trampoline);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildLeaveTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256] = {0};
    ZzCodeSlice *code_slice = NULL;
    ZZSTATUS status = ZZ_SUCCESS;
    bool is_thumb = TRUE;
    ZzARMAssemblerWriter *thumb_writer;

    thumb_writer = &self->thumb_writer;
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);

    // prepare 2 stack space: 1. next_hop 2. entry arg
    zz_thumb_writer_put_sub_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0xc);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // push r7
    zz_thumb_writer_put_ldr_b_reg_address(thumb_writer, ZZ_ARM_REG_R1, (zz_addr_t) entry);
    zz_thumb_writer_put_str_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);
    zz_thumb_writer_put_ldr_reg_reg_offset(thumb_writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP,
                                           0x0); // pop r7
    zz_thumb_writer_put_add_reg_imm(thumb_writer, ZZ_ARM_REG_SP, 0x4);

    // jump to leave_thunk
    zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC, (zz_addr_t) self->leave_thunk);

    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_leave_trampoline = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= LeaveTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return ZZ_DONE;
}

ZZSTATUS ZzActivateTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256] = {0};
    ZzCodeSlice *code_slice = NULL;
    ZzARMHookFunctionEntryBackend *entry_backend = (ZzARMHookFunctionEntryBackend *) entry->backend;
    ZZSTATUS status = ZZ_SUCCESS;
    bool is_thumb = TRUE;
    zz_addr_t target_addr = (zz_addr_t) entry->target_ptr;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t) entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t) entry->target_ptr & ~(zz_addr_t) 1;

    if (is_thumb) {
        ZzThumbAssemblerWriter *thumb_writer;
        thumb_writer = &self->thumb_writer;
        zz_thumb_writer_reset(thumb_writer, temp_code_slice, target_addr);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            if (entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
                zz_thumb_writer_put_b_imm32(thumb_writer,
                                            ((zz_addr_t) entry->on_enter_transfer_trampoline & ~(zz_addr_t) 1) -
                                            (zz_addr_t) thumb_writer->start_pc);
            } else {
                // target address is not aligne 4, need align
                if ((target_addr % 4) &&
                    entry_backend->redirect_code_size == (ZZ_THUMB_FULL_REDIRECT_SIZE + 2))
                    zz_thumb_writer_put_nop(thumb_writer);
                zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC,
                                                    (zz_addr_t) entry->on_enter_transfer_trampoline);
            }
        } else {
            if (entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
                zz_thumb_writer_put_b_imm32(thumb_writer,
                                            ((zz_addr_t) entry->on_enter_transfer_trampoline & ~(zz_addr_t) 1) -
                                            (zz_addr_t) thumb_writer->start_pc);
            } else {
                // target address is not aligne 4, need align
                if ((target_addr % 4) &&
                    entry_backend->redirect_code_size == (ZZ_THUMB_FULL_REDIRECT_SIZE + 2))
                    zz_thumb_writer_put_nop(thumb_writer);
                zz_thumb_writer_put_ldr_reg_address(thumb_writer, ZZ_ARM_REG_PC,
                                                    (zz_addr_t) entry->on_enter_trampoline);
            }
        }
        if (!ZzMemoryPatchCode((zz_addr_t) target_addr, (zz_ptr_t) thumb_writer->w_start_address,
                               thumb_writer->size))
            return ZZ_FAILED;
//        zz_thumb_writer_free(thumb_writer);
    } else {
        ZzARMAssemblerWriter *arm_writer;
        arm_writer = &self->arm_writer;
        zz_arm_writer_reset(arm_writer, temp_code_slice, target_addr);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            if (entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE) {
                zz_arm_writer_put_b_imm(arm_writer,
                                        (zz_addr_t) entry->on_enter_transfer_trampoline -
                                        (zz_addr_t) arm_writer->start_pc);
            } else {
                zz_arm_writer_put_ldr_reg_address(arm_writer, ZZ_ARM_REG_PC,
                                                  (zz_addr_t) entry->on_enter_transfer_trampoline);
            }
        } else {
            if (entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE) {
                zz_arm_writer_put_b_imm(arm_writer,
                                        (zz_addr_t) entry->on_enter_transfer_trampoline -
                                        (zz_addr_t) arm_writer->start_pc);
            } else {
                zz_arm_writer_put_ldr_reg_address(arm_writer, ZZ_ARM_REG_PC,
                                                  (zz_addr_t) entry->on_enter_trampoline);
            }
        }
        if (!ZzMemoryPatchCode((zz_addr_t) target_addr, (zz_ptr_t) arm_writer->w_start_address,
                               arm_writer->size))
            return ZZ_FAILED;
//        zz_arm_writer_free(arm_writer);
    }

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= ActiveTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\tHookZz Target Address: %p\n", entry->target_ptr);
        if(is_thumb) {
            sprintf(buffer + strlen(buffer), "\t\tHookZz Target Address Arch Mode: Thumb\n");
            if(entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\t\tThumb Brach Jump Type: Near Jump(B xxx)\n");
            } else if(entry_backend->redirect_code_size == ZZ_THUMB_FULL_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\t\tThumb Brach Jump Type: Abs Jump(ldr pc, [pc, #x])\n");
            } else if((((zz_addr_t )entry->target_ptr)%4) && entry_backend->redirect_code_size == (ZZ_THUMB_FULL_REDIRECT_SIZE + 2)) {
                sprintf(buffer + strlen(buffer), "\t\tThumb Brach Jump Type: Align Abs Jump(nop; ldr pc, [pc, #x])\n");
            }
        } else {
            sprintf(buffer + strlen(buffer), "\t\tHookZz Target Address Arch Mode: ARM\n");
            if(entry_backend->redirect_code_size == ZZ_ARM_TINY_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\t\tARM Jump Type: Near Jump(B xxx)\n");
            } else if(entry_backend->redirect_code_size == ZZ_ARM_FULL_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\t\tARM Brach Jump Type: Abs Jump(ldr pc, [pc, #-4])\n");
            }
        }

        if(entry->try_near_jump && entry->on_enter_transfer_trampoline)
            sprintf(buffer + strlen(buffer), "\t\ton_enter_transfer_trampoline: %p\n", entry->on_enter_transfer_trampoline);

        if(entry->hook_type == HOOK_TYPE_DBI) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_DBI\n");
            sprintf(buffer + strlen(buffer), "\t\ton_dynamic_binary_instrumentation_trampoline: %p\n", entry->on_dynamic_binary_instrumentation_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if(entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_ONE_INSTRUCTION\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_insn_leave_trampoline: %p\n", entry->on_insn_leave_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if(entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_FUNCTION_via_PRE_POST\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if(entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_FUNCTION_via_REPLACE\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_transfer_trampoline: %p\n", entry->on_enter_transfer_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if(entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_FUNCTION_via_GOT\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
        }
        HookZzDebugInfoLog("%s", buffer);
    }
    return ZZ_DONE_HOOK;
}
