#include "interceptor-arm.h"
#include "backend-arm-helper.h"
#include "custom-bridge-handler.h"
#include <debuglog.h>
#include <stdlib.h>

#define ZZ_THUMB_TINY_REDIRECT_SIZE 4
#define ZZ_THUMB_FULL_REDIRECT_SIZE 8
#define ARM_TINY_REDIRECT_SIZE 4
#define ARM_FULL_REDIRECT_SIZE 8

InterceptorBackend *InteceptorBackendNew(ExecuteMemoryManager *emm) {
    if (!MemoryHelperIsSupportAllocateRXMemory()) {
        DEBUG_LOG_STR("memory is not support allocate r-x Page!");
        return NULL;
    }

    RetStatus status;
    InterceptorBackend *backend = (InterceptorBackend *)malloc0(sizeof(InterceptorBackend));

    arm_writer_init(&backend->arm_writer, NULL, 0);
    arm_reader_init(&backend->arm_reader, NULL);
    arm_relocator_init(&backend->arm_relocator, &backend->arm_reader, &backend->arm_writer);

    thumb_writer_init(&backend->thumb_writer, NULL, 0);
    thumb_reader_init(&backend->thumb_reader, NULL);
    thumb_relocator_init(&backend->thumb_relocator, &backend->thumb_reader, &backend->thumb_writer);

    backend->emm                                   = emm;
    backend->enter_bridge                          = NULL;
    backend->leave_bridge                          = NULL;
    backend->dynamic_binary_instrumentation_bridge = NULL;

    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= Global Interceptor Info ======= \n");
        sprintf(buffer + strlen(buffer), "\tenter_bridge: %p\n", backend->enter_bridge);
        sprintf(buffer + strlen(buffer), "\tleave_bridge: %p\n", backend->leave_bridge);
        sprintf(buffer + strlen(buffer), "\tdynamic_binary_instrumentation_bridge: %p\n",
                backend->dynamic_binary_instrumentation_bridge);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }

    if (status == RS_FAILED) {
        DEBUG_LOG("%s", "BridgeBuildAll return RS_FAILED\n");
        return NULL;
    }

    return backend;
}

void TrampolineFree(HookEntry *entry) {
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
    return;
}

void TrampolinePrepare(InterceptorBackend *self, HookEntry *entry) {
    bool is_thumb            = FALSE;
    zz_addr_t target_addr    = (zz_addr_t)entry->target_ptr;
    zz_size_t redirect_limit = 0;
    ARMHookEntryBackend *entry_backend;

    entry_backend  = (ARMHookEntryBackend *)malloc0(sizeof(ARMHookEntryBackend));
    entry->backend = (struct _HookEntryBackend *)entry_backend;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t)entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t)entry->target_ptr & ~(zz_addr_t)1;

    if (is_thumb) {
        if (entry->try_near_jump) {
            entry_backend->redirect_code_size = ZZ_THUMB_TINY_REDIRECT_SIZE;
        } else {
            // check the first few instructions, preparatory work of instruction-fixing
            thumb_relocator_try_relocate((zz_ptr_t)target_addr, ZZ_THUMB_FULL_REDIRECT_SIZE, &redirect_limit);
            if (redirect_limit != 0 && redirect_limit > ZZ_THUMB_TINY_REDIRECT_SIZE &&
                redirect_limit < ZZ_THUMB_FULL_REDIRECT_SIZE) {
                entry->try_near_jump              = TRUE;
                entry_backend->redirect_code_size = ZZ_THUMB_TINY_REDIRECT_SIZE;
            } else if (redirect_limit != 0 && redirect_limit < ZZ_THUMB_TINY_REDIRECT_SIZE) {
                return;
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
            entry_backend->redirect_code_size = ARM_TINY_REDIRECT_SIZE;
        } else {
            // check the first few instructions, preparatory work of instruction-fixing
            arm_relocator_try_relocate((zz_ptr_t)target_addr, ARM_FULL_REDIRECT_SIZE, &redirect_limit);
            if (redirect_limit != 0 && redirect_limit > ARM_TINY_REDIRECT_SIZE &&
                redirect_limit < ARM_FULL_REDIRECT_SIZE) {
                entry->try_near_jump              = TRUE;
                entry_backend->redirect_code_size = ARM_TINY_REDIRECT_SIZE;
            } else if (redirect_limit != 0 && redirect_limit < ARM_TINY_REDIRECT_SIZE) {
                return;
            } else {
                entry_backend->redirect_code_size = ARM_FULL_REDIRECT_SIZE;
            }
        }
        self->arm_relocator.try_relocated_length = entry_backend->redirect_code_size;
    }

    // save original prologue
    memcpy(entry->origin_prologue.data, (zz_ptr_t)target_addr, entry_backend->redirect_code_size);
    entry->origin_prologue.size    = entry_backend->redirect_code_size;
    entry->origin_prologue.address = (zz_ptr_t)target_addr;

    // relocator initialize
    arm_relocator_init(&self->arm_relocator, &self->arm_reader, &self->arm_writer);
    thumb_relocator_init(&self->thumb_relocator, &self->thumb_reader, &self->thumb_writer);
    return;
}

void TrampolineBuildForEnterTransfer(InterceptorBackend *self, HookEntry *entry) {
    char temp_codeslice[256]           = {0};
    ARMAssemblerWriter *arm_writer     = NULL;
    ARMAssemblerWriter *thumb_writer   = NULL;
    CodeSlice *codeslice               = NULL;
    ARMHookEntryBackend *entry_backend = (ARMHookEntryBackend *)entry->backend;
    RetStatus status                   = RS_SUCCESS;
    bool is_thumb                      = TRUE;
    zz_addr_t target_addr              = (zz_addr_t)entry->target_ptr;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t)entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t)entry->target_ptr & ~(zz_addr_t)1;

    zz_ptr_t temp_codeslice_align = (zz_ptr_t)zz_vm_align_ceil((zz_addr_t)temp_codeslice, 4);

    if (is_thumb) {
        thumb_writer = &self->thumb_writer;
        thumb_writer_reset(thumb_writer, temp_codeslice_align, 0);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {

            thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC, (zz_addr_t)entry->replace_call);
        } else if (entry->hook_type == HOOK_TYPE_DBI) {
            thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC,
                                             (zz_addr_t)entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC, (zz_addr_t)entry->on_enter_trampoline);
        }
        if (entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
            codeslice =
                thumb_code_patch(thumb_writer, self->emm, target_addr, thumb_writer_near_jump_range_size() - 0x10);
        } else {
            codeslice = thumb_code_patch(thumb_writer, self->emm, 0, 0);
        }

        if (codeslice)
            entry->on_enter_transfer_trampoline = codeslice->data + 1;
        else
            return;
    } else {
        arm_writer = &self->arm_writer;
        arm_writer_reset(arm_writer, temp_codeslice_align, 0);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC, (zz_addr_t)entry->replace_call);
        } else if (entry->hook_type == HOOK_TYPE_DBI) {
            arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC,
                                           (zz_addr_t)entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC, (zz_addr_t)entry->on_enter_trampoline);
        }

        if (entry_backend->redirect_code_size == ARM_TINY_REDIRECT_SIZE) {
            codeslice = arm_code_patch(arm_writer, self->emm, target_addr, arm_writer_near_jump_range_size() - 0x10);
        } else {
            codeslice = arm_code_patch(arm_writer, self->emm, 0, 0);
        }
        if (codeslice)
            entry->on_enter_transfer_trampoline = codeslice->data;
        else
            return;
    }

// DELETE ?
#if 0
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= EnterTransferTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\ton_enter_transfer_trampoline: %p\n", entry->on_enter_transfer_trampoline);
        sprintf(buffer + strlen(buffer), "\ttrampoline_length: %ld\n", codeslice->size);
        sprintf(buffer + strlen(buffer), "\thook_entry: %p\n", (void *)entry);
        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            sprintf(buffer + strlen(buffer), "\tjump_target: replace_call(%p)\n", (void *)entry->replace_call);
        } else if (entry->hook_type == HOOK_TYPE_DBI) {
            sprintf(buffer + strlen(buffer), "\tjump_target: on_dynamic_binary_instrumentation_trampoline(%p)\n",
                    (void *)entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            sprintf(buffer + strlen(buffer), "\tjump_target: on_enter_trampoline(%p)\n",
                    (void *)entry->on_enter_trampoline);
        }
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
#endif

    free(codeslice);
    return;
}

void TrampolineBuildForEnter(InterceptorBackend *self, HookEntry *entry) {
    ARMHookEntryBackend *entry_backend = (ARMHookEntryBackend *)entry->backend;
    RetStatus status                   = RS_SUCCESS;
    bool is_thumb;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t)entry->target_ptr);

    ClosureBridgeData *bridgeData;

    bridgeData = ClosureBridgeAllocate(entry, context_begin_invocation_bridge_handler);
    if (bridgeData == NULL) {
        ERROR_LOG_STR("build closure bridge failed!!!");
    }

    entry->on_enter_trampoline = bridgeData->redirect_trampoline;

    // build the double trampline aka enter_transfer_trampoline
    if (entry_backend)
        if ((is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) ||
            (!is_thumb && entry_backend->redirect_code_size == ARM_TINY_REDIRECT_SIZE)) {
            if (entry->hook_type != HOOK_TYPE_FUNCTION_via_GOT) {
                TrampolineBuildForEnterTransfer(self, entry);
            }
        }

// DELETE ?
#if 0
    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= EnterTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
#endif

    return;
}

void TrampolineBuildForDynamicBinaryInstrumentation(InterceptorBackend *self, HookEntry *entry) {
    ARMHookEntryBackend *entry_backend = (ARMHookEntryBackend *)entry->backend;
    RetStatus status                   = RS_SUCCESS;
    bool is_thumb;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t)entry->target_ptr);

    ClosureBridgeData *bridgeData;

    bridgeData = ClosureBridgeAllocate(entry, context_begin_invocation_bridge_handler);
    if (bridgeData == NULL) {
        ERROR_LOG_STR("build closure bridge failed!!!");
    }

    entry->on_dynamic_binary_instrumentation_trampoline = bridgeData->redirect_trampoline;

    // build the double trampline aka enter_transfer_trampoline
    if ((is_thumb && entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) ||
        (!is_thumb && entry_backend->redirect_code_size == ARM_TINY_REDIRECT_SIZE)) {
        if (entry->hook_type != HOOK_TYPE_FUNCTION_via_GOT) {
            TrampolineBuildForEnterTransfer(self, entry);
        }
    }

// DELETE ?
#if 0
    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= DynamicBinaryInstrumentationTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\tdynamic_binary_instrumentation_trampoline: %p\n",
                entry->on_dynamic_binary_instrumentation_trampoline);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
#endif

    return;
}

void TrampolineBuildForInvoke(InterceptorBackend *self, HookEntry *entry) {
    char temp_codeslice[256]           = {0};
    CodeSlice *codeslice               = NULL;
    ARMHookEntryBackend *entry_backend = (ARMHookEntryBackend *)entry->backend;
    RetStatus status                   = RS_SUCCESS;
    bool is_thumb                      = TRUE;
    zz_addr_t target_addr              = (zz_addr_t)entry->target_ptr;
    zz_ptr_t restore_next_insn_addr;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t)entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t)entry->target_ptr & ~(zz_addr_t)1;

    zz_ptr_t temp_codeslice_align = (zz_ptr_t)zz_vm_align_ceil((zz_addr_t)temp_codeslice, 4);

    if (is_thumb) {
        ThumbRelocator *thumb_relocator;
        ThumbAssemblerWriter *thumb_writer;
        ARMReader *thumb_reader;
        thumb_relocator = &self->thumb_relocator;
        thumb_writer    = &self->thumb_writer;
        thumb_reader    = &self->thumb_reader;

        thumb_writer_reset(thumb_writer, temp_codeslice_align, 0);
        thumb_reader_reset(thumb_reader, (zz_ptr_t)target_addr);
        thumb_relocator_reset(thumb_relocator, thumb_reader, thumb_writer);

        {
            do {
                thumb_relocator_read_one(thumb_relocator, NULL);
            } while (thumb_relocator->input->insns_size < entry_backend->redirect_code_size);
            thumb_relocator_write_all(thumb_relocator);
        }

        // jump to rest function instructions address
        restore_next_insn_addr = (zz_ptr_t)((zz_addr_t)target_addr + thumb_relocator->input->insns_size);
        thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC, (zz_addr_t)(restore_next_insn_addr + 1));

        // code patch
        codeslice = thumb_relocate_code_patch(thumb_relocator, thumb_writer, self->emm, 0, 0);
        if (codeslice)
            entry->on_invoke_trampoline = codeslice->data + 1;
        else
            return;
    } else {
        ARMRelocator *arm_relocator;
        ARMAssemblerWriter *arm_writer;
        ARMReader *arm_reader;
        arm_relocator = &self->arm_relocator;
        arm_writer    = &self->arm_writer;
        arm_reader    = &self->arm_reader;

        arm_writer_reset(arm_writer, temp_codeslice_align, 0);
        arm_reader_reset(arm_reader, (zz_ptr_t)target_addr);
        arm_relocator_reset(arm_relocator, arm_reader, arm_writer);

        {
            do {
                arm_relocator_read_one(arm_relocator, NULL);
            } while (arm_relocator->input->insns_size < entry_backend->redirect_code_size);
            arm_relocator_write_all(arm_relocator);
        }

        // jump to rest target address
        restore_next_insn_addr = (zz_ptr_t)((zz_addr_t)target_addr + arm_relocator->input->insns_size);
        arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC, (zz_addr_t)restore_next_insn_addr);

        codeslice = arm_relocate_code_patch(arm_relocator, arm_writer, self->emm, 0, 0);
        if (codeslice)
            entry->on_invoke_trampoline = codeslice->data;
        else
            return;
    }

    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024]         = {};
        char origin_prologue[256] = {0};
        int t                     = 0;

        sprintf(buffer + strlen(buffer), "======= Origin Code Relocator ======= \n");
        if (is_thumb) {
            for(int i = 0; i < self->thumb_relocator.input->insnCTXs_count; i++) {
                sprintf(origin_prologue + t, "0x%.2x ", self->thumb_relocator.input->insnCTXs[i]->insn);

            }
            sprintf(buffer + strlen(buffer), "\t\tThumb Origin Prologue:: %s\n", origin_prologue);
            sprintf(buffer + strlen(buffer), "\tThumb Relocator Input Start Address: %p\n",
                    (zz_ptr_t)self->thumb_relocator.input->insns_buffer);
            sprintf(buffer + strlen(buffer), "\tThumb Relocator Input Instruction Number: %ld\n",
                    self->thumb_relocator.input->insnCTXs_count);
            sprintf(buffer + strlen(buffer), "\tThumb Relocator Input Size: %p\n",
                    (zz_ptr_t)self->thumb_relocator.input->insns_size);
            sprintf(buffer + strlen(buffer), "\tThumb Relocator Output Start Address: %p\n", codeslice->data);
            sprintf(buffer + strlen(buffer), "\tThumb Relocator Output Instruction Number: %p\n",
                    (zz_ptr_t)self->thumb_relocator.input->insnCTXs_count);
            sprintf(buffer + strlen(buffer), "\tThumb Relocator Output Size: %ld\n", self->thumb_relocator.input->insns_size);
            for (int i = 0; i < self->thumb_relocator.relocated_insnCTXs_count; i++) {
                sprintf(buffer + strlen(buffer),
                        "\t\torigin input(%p) -> relocated ouput(%p), relocate %ld instruction\n",
                        (zz_ptr_t)self->thumb_relocator.relocator_insnCTXs[i].origin_insn->address,
                        (zz_ptr_t)self->thumb_relocator.relocator_insnCTXs[i].relocated_insnCTXs[0]->address,
                        self->thumb_relocator.relocator_insnCTXs[i].relocated_insn_size);
            }
        } else {
            for(int i = 0; i < self->arm_relocator.input->insnCTXs_count; i++) {
                sprintf(origin_prologue + t, "0x%.2x ", self->arm_relocator.input->insnCTXs[i]->insn);

            }
            sprintf(buffer + strlen(buffer), "\tARM Origin Prologue: %s\n", origin_prologue);
            sprintf(buffer + strlen(buffer), "\tARM Relocator Input Start Address: %p\n",
                    (zz_ptr_t)self->arm_relocator.input->insns_buffer);
            sprintf(buffer + strlen(buffer), "\tARM Relocator Input Instruction Number: %ld\n",
                    self->arm_relocator.input->insnCTXs_count);
            sprintf(buffer + strlen(buffer), "\tARM Relocator Input Size: %p\n",
                    (zz_ptr_t)self->arm_relocator.input->insns_size);
            sprintf(buffer + strlen(buffer), "\tARM Relocator Output Start Address: %p\n", codeslice->data);
            sprintf(buffer + strlen(buffer), "\tARM Relocator Output Instruction Number: %p\n",
                    (zz_ptr_t)self->arm_relocator.input->insnCTXs_count);
            sprintf(buffer + strlen(buffer), "\tARM Relocator Output Size: %ld\n", self->arm_relocator.input->insns_size);
            for (int i = 0; i < self->arm_relocator.relocated_insnCTXs_count; i++) {
                sprintf(buffer + strlen(buffer),
                        "\t\torigin input(%p) -> relocated ouput(%p), relocate %ld instruction\n",
                        (zz_ptr_t)self->arm_relocator.relocator_insnCTXs[i].origin_insn->address,
                        (zz_ptr_t)self->arm_relocator.relocator_insnCTXs[i].relocated_insnCTXs[0]->address,
                        self->arm_relocator.relocator_insnCTXs[i].relocated_insn_size);
            }
        }
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }

    free(codeslice);
    return;
}

void TrampolineBuildForLeave(InterceptorBackend *self, HookEntry *entry) {
    ClosureBridgeData *bridgeData;

    bridgeData = ClosureBridgeAllocate(entry, context_end_invocation_bridge_handler);
    if (bridgeData == NULL) {
        ERROR_LOG_STR("build closure bridge failed!!!");
    }

    entry->on_leave_trampoline = bridgeData->redirect_trampoline;

// DELETE ?
#if 0
    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= LeaveTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
#endif

    return;
}

void TrampolineActivate(InterceptorBackend *self, HookEntry *entry) {
    char temp_codeslice[256]           = {0};
    CodeSlice *codeslice               = NULL;
    ARMHookEntryBackend *entry_backend = (ARMHookEntryBackend *)entry->backend;
    RetStatus status                   = RS_SUCCESS;
    bool is_thumb                      = TRUE;
    zz_addr_t target_addr              = (zz_addr_t)entry->target_ptr;

    is_thumb = INSTRUCTION_IS_THUMB((zz_addr_t)entry->target_ptr);
    if (is_thumb)
        target_addr = (zz_addr_t)entry->target_ptr & ~(zz_addr_t)1;

    zz_ptr_t temp_codeslice_align = (zz_ptr_t)zz_vm_align_ceil((zz_addr_t)temp_codeslice, 4);

    if (is_thumb) {
        ThumbAssemblerWriter *thumb_writer;
        thumb_writer = &self->thumb_writer;
        thumb_writer_reset(thumb_writer, temp_codeslice_align, target_addr);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            if (entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
                thumb_writer_put_b_imm32(thumb_writer,
                                         ((zz_addr_t)entry->on_enter_transfer_trampoline & ~(zz_addr_t)1) -
                                             (zz_addr_t)thumb_writer->start_pc);
            } else {
                // target address is not aligne 4, need align
                if ((target_addr % 4) && entry_backend->redirect_code_size == (ZZ_THUMB_FULL_REDIRECT_SIZE + 2))
                    thumb_writer_put_nop(thumb_writer);
                thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC,
                                                 (zz_addr_t)entry->on_enter_transfer_trampoline);
            }
        } else {
            if (entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
                thumb_writer_put_b_imm32(thumb_writer,
                                         ((zz_addr_t)entry->on_enter_transfer_trampoline & ~(zz_addr_t)1) -
                                             (zz_addr_t)thumb_writer->start_pc);
            } else {
                // target address is not aligne 4, need align
                if ((target_addr % 4) && entry_backend->redirect_code_size == (ZZ_THUMB_FULL_REDIRECT_SIZE + 2))
                    thumb_writer_put_nop(thumb_writer);
                thumb_writer_put_ldr_reg_address(thumb_writer, ARM_REG_PC, (zz_addr_t)entry->on_enter_trampoline);
            }
        }
        if (!MemoryHelperPatchCode((zz_addr_t)target_addr, (zz_ptr_t)thumb_writer->insns_buffer, thumb_writer->insns_size))
            return;
        //        thumb_writer_free(thumb_writer);
    } else {
        ARMAssemblerWriter *arm_writer;
        arm_writer = &self->arm_writer;
        arm_writer_reset(arm_writer, temp_codeslice_align, target_addr);

        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            if (entry_backend->redirect_code_size == ARM_TINY_REDIRECT_SIZE) {
                arm_writer_put_b_imm(arm_writer,
                                     (zz_addr_t)entry->on_enter_transfer_trampoline - (zz_addr_t)arm_writer->start_pc);
            } else {
                arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC, (zz_addr_t)entry->on_enter_transfer_trampoline);
            }
        } else {
            if (entry_backend->redirect_code_size == ARM_TINY_REDIRECT_SIZE) {
                arm_writer_put_b_imm(arm_writer,
                                     (zz_addr_t)entry->on_enter_transfer_trampoline - (zz_addr_t)arm_writer->start_pc);
            } else {
                arm_writer_put_ldr_reg_address(arm_writer, ARM_REG_PC, (zz_addr_t)entry->on_enter_trampoline);
            }
        }
        if (!MemoryHelperPatchCode((zz_addr_t)target_addr, (zz_ptr_t)arm_writer->insns_buffer, arm_writer->insns_size))
            return;
        //        arm_writer_free(arm_writer);
    }

    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "======= Trampoline Summary ======= \n");
        sprintf(buffer + strlen(buffer), "\tHookZz Target Address: %p\n", entry->target_ptr);
        if (is_thumb) {
            sprintf(buffer + strlen(buffer), "\tHookZz Target Address Arch Mode: Thumb\n");
            if (entry_backend->redirect_code_size == ZZ_THUMB_TINY_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\tThumb Brach Jump Type: Near Jump(B xxx)\n");
            } else if (entry_backend->redirect_code_size == ZZ_THUMB_FULL_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\tThumb Brach Jump Type: Abs Jump(ldr pc, [pc, #x])\n");
            } else if ((((zz_addr_t)entry->target_ptr) % 4) &&
                       entry_backend->redirect_code_size == (ZZ_THUMB_FULL_REDIRECT_SIZE + 2)) {
                sprintf(buffer + strlen(buffer), "\tThumb Brach Jump Type: Align Abs Jump(nop; ldr pc, [pc, #x])\n");
            }
        } else {
            sprintf(buffer + strlen(buffer), "\tHookZz Target Address Arch Mode: ARM\n");
            if (entry_backend->redirect_code_size == ARM_TINY_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\tARM Jump Type: Near Jump(B xxx)\n");
            } else if (entry_backend->redirect_code_size == ARM_FULL_REDIRECT_SIZE) {
                sprintf(buffer + strlen(buffer), "\tARM Brach Jump Type: Abs Jump(ldr pc, [pc, #-4])\n");
            }
        }

        if (entry->try_near_jump && entry->on_enter_transfer_trampoline)
            sprintf(buffer + strlen(buffer), "\ton_enter_transfer_trampoline: %p\n",
                    entry->on_enter_transfer_trampoline);

        if (entry->hook_type == HOOK_TYPE_DBI) {
            sprintf(buffer + strlen(buffer), "\tHook Type: HOOK_TYPE_DBI\n");
            sprintf(buffer + strlen(buffer), "\ton_dynamic_binary_instrumentation_trampoline: %p\n",
                    entry->on_dynamic_binary_instrumentation_trampoline);
            sprintf(buffer + strlen(buffer), "\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
            sprintf(buffer + strlen(buffer), "\tHook Type: HOOK_TYPE_FUNCTION_via_PRE_POST\n");
            sprintf(buffer + strlen(buffer), "\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
            sprintf(buffer + strlen(buffer), "\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            sprintf(buffer + strlen(buffer), "\tHook Type: HOOK_TYPE_FUNCTION_via_REPLACE\n");
            sprintf(buffer + strlen(buffer), "\ton_enter_transfer_trampoline: %p\n",
                    entry->on_enter_transfer_trampoline);
            sprintf(buffer + strlen(buffer), "\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
            sprintf(buffer + strlen(buffer), "\tHook Type: HOOK_TYPE_FUNCTION_via_GOT\n");
            sprintf(buffer + strlen(buffer), "\ton_enter_trampoline: %p\n", entry->on_enter_trampoline);
            sprintf(buffer + strlen(buffer), "\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
        }
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
    return;
}
