#include "interceptor-arm64.h"
#include "backend-arm64-helper.h"
#include "thunker-arm64.h"

#include <stdlib.h>
#include <string.h>

#define ZZ_ARM64_TINY_REDIRECT_SIZE 4
#define ZZ_ARM64_FULL_REDIRECT_SIZE 16

ZzInterceptorBackend *ZzBuildInteceptorBackend(ZzAllocator *allocator) {
    if (!ZzMemoryIsSupportAllocateRXPage()) {
        ZZ_DEBUG_LOG_STR("memory is not support allocate r-x Page!");
        return NULL;
    }

    ZZSTATUS status;
    ZzInterceptorBackend *backend = (ZzInterceptorBackend *)zz_malloc_with_zero(sizeof(ZzInterceptorBackend));

    zz_arm64_writer_init(&backend->arm64_writer, NULL, 0);
    zz_arm64_reader_init(&backend->arm64_reader, NULL);
    zz_arm64_relocator_init(&backend->arm64_relocator, &backend->arm64_reader, &backend->arm64_writer);

    backend->allocator                            = allocator;
    backend->enter_thunk                          = NULL;
    backend->insn_leave_thunk                     = NULL;
    backend->leave_thunk                          = NULL;
    backend->dynamic_binary_instrumentation_thunk = NULL;

    // build enter/leave/inovke thunk
    status = ZzThunkerBuildThunk(backend);

    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= Global Interceptor Info ======= \n");
        sprintf(buffer + strlen(buffer), "\t\tenter_thunk: %p\n", backend->enter_thunk);
        sprintf(buffer + strlen(buffer), "\t\tleave_thunk: %p\n", backend->leave_thunk);
        sprintf(buffer + strlen(buffer), "\t\tinsn_leave_thunk: %p\n", backend->insn_leave_thunk);
        sprintf(buffer + strlen(buffer), "\t\tdynamic_binary_instrumentation_thunk: %p\n",
                backend->dynamic_binary_instrumentation_thunk);
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
    zz_addr_t target_addr    = (zz_addr_t)entry->target_ptr;
    zz_size_t redirect_limit = 0;
    ZzARM64HookFunctionEntryBackend *entry_backend;

    entry_backend  = (ZzARM64HookFunctionEntryBackend *)zz_malloc_with_zero(sizeof(ZzARM64HookFunctionEntryBackend));
    entry->backend = (struct _ZzHookFunctionEntryBackend *)entry_backend;

    if (entry->try_near_jump) {
        entry_backend->redirect_code_size = ZZ_ARM64_TINY_REDIRECT_SIZE;
    } else {
        // check the first few instructions, preparatory work of instruction-fix
        zz_arm64_relocator_try_relocate((zz_ptr_t)target_addr, ZZ_ARM64_FULL_REDIRECT_SIZE, &redirect_limit);
        if (redirect_limit != 0 && redirect_limit > ZZ_ARM64_TINY_REDIRECT_SIZE &&
            redirect_limit < ZZ_ARM64_FULL_REDIRECT_SIZE) {
            entry->try_near_jump              = TRUE;
            entry_backend->redirect_code_size = ZZ_ARM64_TINY_REDIRECT_SIZE;
        } else if (redirect_limit != 0 && redirect_limit < ZZ_ARM64_TINY_REDIRECT_SIZE) {
            return ZZ_FAILED;
        } else {
            entry_backend->redirect_code_size = ZZ_ARM64_FULL_REDIRECT_SIZE;
        }
    }

    self->arm64_relocator.try_relocated_length = entry_backend->redirect_code_size;

    // save original prologue
    memcpy(entry->origin_prologue.data, (zz_ptr_t)target_addr, entry_backend->redirect_code_size);
    entry->origin_prologue.size    = entry_backend->redirect_code_size;
    entry->origin_prologue.address = (zz_ptr_t)target_addr;

    // relocator initialize
    zz_arm64_relocator_init(&self->arm64_relocator, (zz_ptr_t)target_addr, &self->arm64_writer);
    return ZZ_SUCCESS;
}

// double jump
ZZSTATUS ZzBuildEnterTransferTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256]                      = {0};
    ZzARM64AssemblerWriter *arm64_writer           = NULL;
    ZzCodeSlice *code_slice                        = NULL;
    ZzARM64HookFunctionEntryBackend *entry_backend = (ZzARM64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status                                = ZZ_SUCCESS;
    zz_addr_t target_addr                          = (zz_addr_t)entry->target_ptr;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice, 0);
    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)entry->replace_call);
    } else if (entry->hook_type == HOOK_TYPE_DBI) {
        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17,
                                               (zz_addr_t)entry->on_dynamic_binary_instrumentation_trampoline);
    } else {
        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)entry->on_enter_trampoline);
    }

    if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
        code_slice = zz_arm64_code_patch(arm64_writer, self->allocator, target_addr,
                                         zz_arm64_writer_near_jump_range_size() - 0x10);
    } else {
        code_slice = zz_arm64_code_patch(arm64_writer, self->allocator, 0, 0);
    }

    if (code_slice)
        entry->on_enter_transfer_trampoline = code_slice->data;
    else
        return ZZ_FAILED;

    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= EnterTransferTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\ton_enter_transfer_trampoline: %p\n", entry->on_enter_transfer_trampoline);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        sprintf(buffer + strlen(buffer), "\t\thook_entry: %p\n", (void *)entry);
        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            sprintf(buffer + strlen(buffer), "\t\tjump_target: replace_call(%p)\n", (void *)entry->replace_call);
        } else if (entry->hook_type == HOOK_TYPE_DBI) {
            sprintf(buffer + strlen(buffer), "\t\tjump_target: on_dynamic_binary_instrumentation_trampoline(%p)\n",
                    (void *)entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            sprintf(buffer + strlen(buffer), "\t\tjump_target: on_enter_trampoline(%p)\n",
                    (void *)entry->on_enter_trampoline);
        }
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildEnterTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256]                      = {0};
    ZzARM64AssemblerWriter *arm64_writer           = NULL;
    ZzCodeSlice *code_slice                        = NULL;
    ZzARM64HookFunctionEntryBackend *entry_backend = (ZzARM64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status                                = ZZ_SUCCESS;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice, 0);

    // prepare 2 stack space: 1. next_hop 2. entry arg
    zz_arm64_writer_put_sub_reg_reg_imm(arm64_writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 0x8);
    zz_arm64_writer_put_ldr_b_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)entry);
    zz_arm64_writer_put_str_reg_reg_offset(arm64_writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x0);

    // jump to enter thunk
    zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)self->enter_thunk);

    code_slice = zz_arm64_code_patch(arm64_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_enter_trampoline = code_slice->data;
    else
        return ZZ_FAILED;

    // build the double trampline aka enter_transfer_trampoline
    if (entry->hook_type != HOOK_TYPE_FUNCTION_via_GOT)
        if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
            ZzBuildEnterTransferTrampoline(self, entry);
        }

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= EnterTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", code_slice->data);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        sprintf(buffer + strlen(buffer), "\t\tjump_target: enter_thunk(%p)\n", (void *)self->enter_thunk);
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildDynamicBinaryInstrumentationTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256]                      = {0};
    ZzARM64AssemblerWriter *arm64_writer           = NULL;
    ZzCodeSlice *code_slice                        = NULL;
    ZzARM64HookFunctionEntryBackend *entry_backend = (ZzARM64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status                                = ZZ_SUCCESS;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice, 0);

    // prepare 2 stack space: 1. next_hop 2. entry arg
    zz_arm64_writer_put_sub_reg_reg_imm(arm64_writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 0x8);
    zz_arm64_writer_put_ldr_b_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)entry);
    zz_arm64_writer_put_str_reg_reg_offset(arm64_writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x0);

    // jump to enter thunk
    zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17,
                                           (zz_addr_t)self->dynamic_binary_instrumentation_thunk);

    code_slice = zz_arm64_code_patch(arm64_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_enter_trampoline = code_slice->data;
    else
        return ZZ_FAILED;

    // build the double trampline aka enter_transfer_trampoline
    if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
        ZzBuildEnterTransferTrampoline(self, entry);
    }

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= DynamicBinaryInstrumentationTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\tdynamic_binary_instrumentation_trampoline: %p\n",
                entry->on_dynamic_binary_instrumentation_trampoline);
        sprintf(buffer + strlen(buffer), "\t\ttrampoline_length: %ld\n", code_slice->size);
        sprintf(buffer + strlen(buffer), "\t\thook_entry: %p\n", (void *)entry);
        sprintf(buffer + strlen(buffer), "\t\tjump_target: dynamic_binary_instrumentation_thunk(%p)\n",
                (void *)self->dynamic_binary_instrumentation_thunk);
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildInvokeTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256]                      = {0};
    ZzCodeSlice *code_slice                        = NULL;
    ZzARM64HookFunctionEntryBackend *entry_backend = (ZzARM64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status                                = ZZ_SUCCESS;
    zz_addr_t target_addr                          = (zz_addr_t)entry->target_ptr;
    zz_ptr_t restore_next_insn_addr;
    ZzARM64Relocator *arm64_relocator;
    ZzARM64AssemblerWriter *arm64_writer;
    ZzARM64Reader *arm64_reader;

    arm64_relocator = &self->arm64_relocator;
    arm64_writer    = &self->arm64_writer;
    arm64_reader    = &self->arm64_reader;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice, 0);
    zz_arm64_reader_reset(arm64_reader, (zz_ptr_t)target_addr);
    zz_arm64_relocator_reset(arm64_relocator, arm64_reader, arm64_writer);

    if (entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
        zz_arm64_relocator_read_one(arm64_relocator, NULL);
        zz_arm64_relocator_write_one(arm64_relocator);

        zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17,
                                               (zz_addr_t)entry->on_insn_leave_trampoline);

        do {
            zz_arm64_relocator_read_one(arm64_relocator, NULL);
            zz_arm64_relocator_write_one(arm64_relocator);
        } while (arm64_relocator->input->size < entry_backend->redirect_code_size);
    } else {
        do {
            zz_arm64_relocator_read_one(arm64_relocator, NULL);
        } while (arm64_relocator->input->size < entry_backend->redirect_code_size);
        zz_arm64_relocator_write_all(arm64_relocator);
    }

    // jump to rest target address
    restore_next_insn_addr = (zz_ptr_t)((zz_addr_t)target_addr + arm64_relocator->input->size);
    zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)restore_next_insn_addr);

    code_slice = zz_arm64_relocate_code_patch(arm64_relocator, arm64_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_invoke_trampoline = code_slice->data;
    else
        return ZZ_FAILED;

    //
    if (entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
        ZzARM64RelocatorInstruction relocator_insn = arm64_relocator->relocator_insns[1];
        entry->next_insn_addr =
            (relocator_insn.relocated_insns[0]->pc - arm64_relocator->output->start_pc) + (zz_addr_t)code_slice->data;
    }

    /* debug log */
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024]         = {};
        char origin_prologue[256] = {0};
        int t                     = 0;
        for (zz_addr_t p = self->arm64_relocator.input->r_start_address;
             p < self->arm64_relocator.input->r_current_address; p++, t = t + 5) {
            sprintf(origin_prologue + t, "0x%.2x ", *(unsigned char *)p);
        }
        sprintf(buffer + strlen(buffer), "\t\t\tARM Origin Prologue: %s\n", origin_prologue);
        sprintf(buffer + strlen(buffer), "\t\tARM Relocator Input Start Address: %p\n",
                (zz_ptr_t)self->arm64_relocator.input->r_start_address);
        sprintf(buffer + strlen(buffer), "\t\tARM Relocator Input Instruction Number: %ld\n",
                self->arm64_relocator.input->insn_size);
        sprintf(buffer + strlen(buffer), "\t\tARM Relocator Input Size: %p\n",
                (zz_ptr_t)self->arm64_relocator.input->size);
        sprintf(buffer + strlen(buffer), "\t\tARM Relocator Output Start Address: %p\n", code_slice->data);
        sprintf(buffer + strlen(buffer), "\t\tARM Relocator Output Instruction Number: %p\n",
                (zz_ptr_t)self->arm64_relocator.input->insn_size);
        sprintf(buffer + strlen(buffer), "\t\tARM Relocator Output Size: %ld\n", self->arm64_relocator.input->size);
        for (int i = 0; i < self->arm64_relocator.relocator_insn_size; i++) {
            sprintf(buffer + strlen(buffer),
                    "\t\t\torigin input(%p) -> relocated ouput(%p), relocate %ld instruction\n",
                    (zz_ptr_t)self->arm64_relocator.relocator_insns[i].origin_insn->address,
                    (zz_ptr_t)self->arm64_relocator.relocator_insns[i].relocated_insns[0]->address,
                    self->arm64_relocator.relocator_insns[i].relocated_insn_size);
        }
        HookZzDebugInfoLog("%s", buffer);
    }

    free(code_slice);
    return status;
}

ZZSTATUS ZzBuildInsnLeaveTrampoline(ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    char temp_code_slice[256]                      = {0};
    ZzARM64AssemblerWriter *arm64_writer           = NULL;
    ZzCodeSlice *code_slice                        = NULL;
    ZzARM64HookFunctionEntryBackend *entry_backend = (ZzARM64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status                                = ZZ_SUCCESS;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice, 0);

    // prepare 2 stack space: 1. next_hop 2. entry arg
    zz_arm64_writer_put_sub_reg_reg_imm(arm64_writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 0x8);
    zz_arm64_writer_put_ldr_b_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)entry);
    zz_arm64_writer_put_str_reg_reg_offset(arm64_writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x0);

    zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)self->insn_leave_thunk);

    code_slice = zz_arm64_code_patch(arm64_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_insn_leave_trampoline = code_slice->data;
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
    char temp_code_slice[256]                      = {0};
    ZzCodeSlice *code_slice                        = NULL;
    ZzARM64HookFunctionEntryBackend *entry_backend = (ZzARM64HookFunctionEntryBackend *)entry->backend;
    ZzARM64AssemblerWriter *arm64_writer           = NULL;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice, 0);

    // prepare 2 stack space: 1. next_hop 2. entry arg
    zz_arm64_writer_put_sub_reg_reg_imm(arm64_writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 0x8);
    zz_arm64_writer_put_ldr_b_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)entry);
    zz_arm64_writer_put_str_reg_reg_offset(arm64_writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x0);

    zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17, (zz_addr_t)self->leave_thunk);

    code_slice = zz_arm64_code_patch(arm64_writer, self->allocator, 0, 0);
    if (code_slice)
        entry->on_leave_trampoline = code_slice->data;
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
    char temp_code_slice[256]                      = {0};
    ZzCodeSlice *code_slice                        = NULL;
    ZzARM64HookFunctionEntryBackend *entry_backend = (ZzARM64HookFunctionEntryBackend *)entry->backend;
    ZZSTATUS status                                = ZZ_SUCCESS;
    zz_addr_t target_addr                          = (zz_addr_t)entry->target_ptr;
    ZzARM64AssemblerWriter *arm64_writer;

    arm64_writer = &self->arm64_writer;
    zz_arm64_writer_reset(arm64_writer, temp_code_slice, target_addr);

    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
        if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
            zz_arm64_writer_put_b_imm(arm64_writer, (zz_addr_t)entry->on_enter_transfer_trampoline -
                                                        (zz_addr_t)arm64_writer->start_pc);
        } else {
            zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17,
                                                   (zz_addr_t)entry->on_enter_transfer_trampoline);
        }
    } else {
        if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
            zz_arm64_writer_put_b_imm(arm64_writer, (zz_addr_t)entry->on_enter_transfer_trampoline -
                                                        (zz_addr_t)arm64_writer->start_pc);
        } else {
            zz_arm64_writer_put_ldr_br_reg_address(arm64_writer, ZZ_ARM64_REG_X17,
                                                   (zz_addr_t)entry->on_enter_trampoline);
        }
    }

    if (!ZzMemoryPatchCode((zz_addr_t)target_addr, (zz_ptr_t)arm64_writer->w_start_address, arm64_writer->size))
        status = ZZ_FAILED;

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= ActiveTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\t\tHookZz Target Address: %p\n", entry->target_ptr);

        sprintf(buffer + strlen(buffer), "\t\tHookZz Target Address Arch Mode: ARM64\n");
        if (entry_backend->redirect_code_size == ZZ_ARM64_TINY_REDIRECT_SIZE) {
            sprintf(buffer + strlen(buffer), "\t\tARM64 Jump Type: Near Jump(B xxx)\n");
        } else if (entry_backend->redirect_code_size == ZZ_ARM64_FULL_REDIRECT_SIZE) {
            sprintf(buffer + strlen(buffer), "\t\tARM64 Brach Jump Type: Abs Jump(ldr r17, #4; .long address)\n");
        }

        if (entry->try_near_jump && entry->on_enter_transfer_trampoline)
            sprintf(buffer + strlen(buffer), "\t\ton_enter_transfer_trampoline: %p\n",
                    entry->on_enter_transfer_trampoline);

        if (entry->hook_type == HOOK_TYPE_DBI) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_DBI\n");
            sprintf(buffer + strlen(buffer), "\t\ton_dynamic_binary_instrumentation_trampoline: %p\n",
                    entry->on_dynamic_binary_instrumentation_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if (entry->hook_type == HOOK_TYPE_ONE_INSTRUCTION) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_ONE_INSTRUCTION\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_insn_leave_trampoline: %p\n", entry->on_insn_leave_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_FUNCTION_via_PRE_POST\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_FUNCTION_via_REPLACE\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_transfer_trampoline: %p\n",
                    entry->on_enter_transfer_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
            sprintf(buffer + strlen(buffer), "\t\tHook Type: HOOK_TYPE_FUNCTION_via_GOT\n");
            sprintf(buffer + strlen(buffer), "\t\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\t\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
        }
        HookZzDebugInfoLog("%s", buffer);
    }

    return status;
}

#ifdef TARGET_IS_IOS

#include "MachoKit/macho_kit.h"
#include <mach-o/dyld.h>

typedef struct _ZzInterceptorBackendNoJB {
    void *enter_thunk; // hardcode
    void *leave_thunk; // hardcode
    unsigned long num_of_entry;
    unsigned long code_seg_offset;
    unsigned long data_seg_offset;
} ZzInterceptorBackendNoJB;

typedef struct _ZzHookFunctionEntryNoJB {
    void *target_fileoff;
    unsigned long is_near_jump;
    void *entry_address;
    void *on_enter_trampoline;  // HookZzData, 99% hardcode
    void *on_invoke_trampoline; // HookZzData, fixed instructions
    void *on_leave_trampoline;  // HookZzData, 99% hardcode
} ZzHookFunctionEntryNoJB;

ZZSTATUS ZzActivateStaticBinaryInstrumentationTrampoline(ZzHookFunctionEntry *entry, zz_addr_t target_fileoff) {
    struct mach_header_64 *header           = (struct mach_header_64 *)_dyld_get_image_header(0);
    struct segment_command_64 *text_seg_cmd = zz_macho_get_segment_64_via_name(header, "__TEXT");
    struct segment_command_64 *data_seg_cmd = zz_macho_get_segment_64_via_name(header, "HookZzData");
    zz_addr_t aslr_slide                    = (zz_addr_t)header - text_seg_cmd->vmaddr;
    ZzInterceptorBackendNoJB *nojb_backend  = (ZzInterceptorBackendNoJB *)(aslr_slide + data_seg_cmd->vmaddr);
    nojb_backend->enter_thunk               = (void *)enter_thunk_template;
    nojb_backend->leave_thunk               = (void *)leave_thunk_template;

    ZzHookFunctionEntryNoJB *nojb_entry =
        (ZzHookFunctionEntryNoJB *)(data_seg_cmd->vmaddr + sizeof(ZzHookFunctionEntryNoJB) + aslr_slide);
    unsigned long i;
    for (i = 0; i < nojb_backend->num_of_entry; i++) {
        nojb_entry = &nojb_entry[i];
        if ((zz_addr_t)nojb_entry->target_fileoff == target_fileoff) {
            nojb_entry->entry_address   = entry;
            entry->on_enter_trampoline  = (zz_ptr_t)(nojb_entry->on_enter_trampoline + aslr_slide);
            entry->on_invoke_trampoline = nojb_entry->on_invoke_trampoline + aslr_slide;
            entry->on_leave_trampoline  = nojb_entry->on_leave_trampoline + aslr_slide;
        }
    }
    return ZZ_SUCCESS;
}
#endif
