#include "interceptor-arm64.h"
#include "backend-arm64-helper.h"
#include "closure-bridge-arm64.h"

#include "custom-bridge-handler.h"
#include "macros.h"

#include <debuglog.h>
#include <stdlib.h>
#include <string.h>

#define ARM64_TINY_REDIRECT_SIZE 4
#define ARM64_FULL_REDIRECT_SIZE 16

InterceptorBackend *InteceptorBackendNew(ExecuteMemoryManager *emm) {
    if (!MemoryHelperIsSupportAllocateRXMemory()) {
        ERROR_LOG_STR("memory is not support allocate r-x page!");
        return NULL;
    }

    RetStatus status            = RS_SUCCESS;
    InterceptorBackend *backend = (InterceptorBackend *)malloc0(sizeof(InterceptorBackend));

    arm64_writer_init(&backend->arm64_writer, 0, 0);
    arm64_reader_init(&backend->arm64_reader, 0);
    arm64_relocator_init(&backend->arm64_relocator, &backend->arm64_reader, &backend->arm64_writer);

    backend->emm                                   = emm;
    backend->enter_bridge                          = NULL;
    backend->insn_leave_bridge                     = NULL;
    backend->leave_bridge                          = NULL;
    backend->dynamic_binary_instrumentation_bridge = NULL;

    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= Global Interceptor Info ======= \n");
        sprintf(buffer + strlen(buffer), "\tenter_bridge: %p\n", backend->enter_bridge);
        sprintf(buffer + strlen(buffer), "\tleave_bridge: %p\n", backend->leave_bridge);
        sprintf(buffer + strlen(buffer), "\tinsn_leave_bridge: %p\n", backend->insn_leave_bridge);
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
    zz_addr_t target_addr    = (zz_addr_t)entry->target_ptr;
    zz_size_t redirect_limit = 0;
    ARM64HookEntryBackend *entry_backend;

    entry_backend  = (ARM64HookEntryBackend *)malloc0(sizeof(ARM64HookEntryBackend));
    entry->backend = (struct _HookEntryBackend *)entry_backend;

    if (entry->try_near_jump) {
        entry_backend->redirect_code_size = ARM64_TINY_REDIRECT_SIZE;
    } else {
        // check the first few instructions, preparatory work of instruction-fix
        arm64_relocator_try_relocate((zz_ptr_t)target_addr, ARM64_FULL_REDIRECT_SIZE, &redirect_limit);
        if (redirect_limit != 0 && redirect_limit > ARM64_TINY_REDIRECT_SIZE &&
            redirect_limit < ARM64_FULL_REDIRECT_SIZE) {
            entry->try_near_jump              = TRUE;
            entry_backend->redirect_code_size = ARM64_TINY_REDIRECT_SIZE;
        } else if (redirect_limit != 0 && redirect_limit < ARM64_TINY_REDIRECT_SIZE) {
            return;
        } else {
            entry_backend->redirect_code_size = ARM64_FULL_REDIRECT_SIZE;
        }
    }

    self->arm64_relocator.try_relocated_length = entry_backend->redirect_code_size;

    // save original prologue
    memcpy(entry->origin_prologue.data, (zz_ptr_t)target_addr, entry_backend->redirect_code_size);
    entry->origin_prologue.size    = entry_backend->redirect_code_size;
    entry->origin_prologue.address = (zz_ptr_t)target_addr;

    // arm64_relocator initialize
    arm64_relocator_init(&self->arm64_relocator, (zz_ptr_t)target_addr, &self->arm64_writer);
    return;
}

// double jump
void TrampolineBuildForEnterTransfer(InterceptorBackend *self, HookEntry *entry) {
    char temp_codeslice[256]             = {0};
    ARM64AssemblyrWriter *arm64_writer   = NULL;
    CodeSlice *codeslice                 = NULL;
    ARM64HookEntryBackend *entry_backend = (ARM64HookEntryBackend *)entry->backend;
    RetStatus status                     = RS_SUCCESS;
    zz_addr_t target_addr                = (zz_addr_t)entry->target_ptr;

    arm64_writer = &self->arm64_writer;
    arm64_writer_reset(arm64_writer, ALIGN_CEIL(temp_codeslice, 4), 0);
    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
        arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17, (zz_addr_t)entry->replace_call);
    } else if (entry->hook_type == HOOK_TYPE_DBI) {
        arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                            (zz_addr_t)entry->on_dynamic_binary_instrumentation_trampoline);
    } else {
        arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17, (zz_addr_t)entry->on_enter_trampoline);
    }

    if (entry_backend->redirect_code_size == ARM64_TINY_REDIRECT_SIZE) {
        codeslice = arm64_code_patch(arm64_writer, self->emm, target_addr, arm64_writer_near_jump_range_size() - 0x10);
    } else {
        codeslice = arm64_code_patch(arm64_writer, self->emm, 0, 0);
    }

    if (codeslice)
        entry->on_enter_transfer_trampoline = codeslice->data;
    else
        return;

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
    ARM64HookEntryBackend *entry_backend = (ARM64HookEntryBackend *)entry->backend;
    RetStatus status                     = RS_SUCCESS;
    ClosureBridgeData *bridgeData;

    bridgeData = ClosureBridgeAllocate(entry, context_begin_invocation_bridge_handler);
    if (bridgeData == NULL) {
        ERROR_LOG_STR("build closure bridge failed!!!");
    }

    entry->on_enter_trampoline = bridgeData->redirect_trampoline;

    // build the double trampline aka enter_transfer_trampoline
    if (entry_backend && entry_backend->redirect_code_size == ARM64_TINY_REDIRECT_SIZE) {
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
        sprintf(buffer + strlen(buffer), "\ton_enter_trampoline: %p\n", bridgeData->redirect_trampoline);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
#endif

    return;
}

void TrampolineBuildForEnterOnly(InterceptorBackend *self, HookEntry *entry) {
    ARM64HookEntryBackend *entry_backend = (ARM64HookEntryBackend *)entry->backend;
    ClosureBridgeData *bridgeData;

    bridgeData = ClosureBridgeAllocate(entry, context_begin_only_invocation_bridge_handler);
    if (bridgeData == NULL) {
        ERROR_LOG_STR("build closure bridge failed!!!");
    }

    entry->on_enter_trampoline = bridgeData->redirect_trampoline;

    // build the double trampline aka enter_transfer_trampoline
    if (entry_backend && entry_backend->redirect_code_size == ARM64_TINY_REDIRECT_SIZE) {
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

void TrampolineBuildForDynamicBinaryInstrumentation(InterceptorBackend *self, HookEntry *entry) {
    ARM64HookEntryBackend *entry_backend = (ARM64HookEntryBackend *)entry->backend;
    ClosureBridgeData *bridgeData;

    bridgeData = ClosureBridgeAllocate(entry, dynamic_binary_instrumentationn_bridge_handler);
    if (bridgeData == NULL) {
        ERROR_LOG_STR("build closure bridge failed!!!");
    }

    entry->on_dynamic_binary_instrumentation_trampoline = bridgeData->redirect_trampoline;

    // build the double trampline aka enter_transfer_trampoline
    if (entry_backend->redirect_code_size == ARM64_TINY_REDIRECT_SIZE) {
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
    char temp_codeslice[256]             = {0};
    CodeSlice *codeslice                 = NULL;
    ARM64HookEntryBackend *entry_backend = (ARM64HookEntryBackend *)entry->backend;
    RetStatus status                     = RS_SUCCESS;
    zz_addr_t target_addr                = (zz_addr_t)entry->target_ptr;
    zz_ptr_t restore_next_insn_addr;
    ARM64Relocator *arm64_relocator;
    ARM64AssemblyrWriter *arm64_writer;
    ARM64AssemblyReader *arm64_reader;

    arm64_relocator = &self->arm64_relocator;
    arm64_writer    = &self->arm64_writer;
    arm64_reader    = &self->arm64_reader;
    arm64_writer_reset(arm64_writer, ALIGN_CEIL(temp_codeslice, 4), 0);
    arm64_reader_reset(arm64_reader, (zz_ptr_t)target_addr);
    arm64_relocator_reset(arm64_relocator, arm64_reader, arm64_writer);

    {
        do {
            arm64_relocator_read_one(arm64_relocator, NULL);
        } while (arm64_relocator->input->insns_size < entry_backend->redirect_code_size);
        arm64_relocator_write_all(arm64_relocator);
    }

    // jump to rest target address
    restore_next_insn_addr = (zz_ptr_t)((zz_addr_t)target_addr + arm64_relocator->input->insns_size);
    arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17, (zz_addr_t)restore_next_insn_addr);

    codeslice = arm64_relocate_code_patch(arm64_relocator, arm64_writer, self->emm, 0, 0);
    if (codeslice)
        entry->on_invoke_trampoline = codeslice->data;
    else
        return;

    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024]         = {};
        char origin_prologue[256] = {0};
        int t                     = 0;
        sprintf(buffer + strlen(buffer), "\n======= Origin Code arm64_relocator ======= \n");
        for (int i = 0; i < self->arm64_relocator.input->insnCTXs_count; i++) {
            sprintf(origin_prologue + t, "0x%.2x ", self->arm64_relocator.input->insnCTXs[i]->insn);
        }
        sprintf(buffer + strlen(buffer), "\tARM Origin Prologue: %s\n", origin_prologue);
        sprintf(buffer + strlen(buffer), "\tARM arm64_relocator Input Start Address: %p\n",
                (zz_ptr_t)self->arm64_relocator.input->insns_buffer);
        sprintf(buffer + strlen(buffer), "\tARM arm64_relocator Input Instruction Number: %ld\n",
                self->arm64_relocator.input->insnCTXs_count);
        sprintf(buffer + strlen(buffer), "\tARM arm64_relocator Input Size: %p\n",
                (zz_ptr_t)self->arm64_relocator.input->insns_size);
        sprintf(buffer + strlen(buffer), "\tARM arm64_relocator Output Start Address: %p\n", codeslice->data);
        sprintf(buffer + strlen(buffer), "\tARM arm64_relocator Output Instruction Number: %p\n",
                (zz_ptr_t)self->arm64_relocator.input->insnCTXs_count);
        sprintf(buffer + strlen(buffer), "\tARM arm64_relocator Output Size: %ld\n",
                self->arm64_relocator.input->insns_size);
        for (int i = 0; i < self->arm64_relocator.relocated_insnCTXs_count; i++) {
            sprintf(buffer + strlen(buffer), "\t\torigin input(%p) -> relocated ouput(%p), relocate %ld instruction\n",
                    (zz_ptr_t)self->arm64_relocator.relocator_insnCTXs[i].origin_insn->address,
                    (zz_ptr_t)self->arm64_relocator.relocator_insnCTXs[i].relocated_insnCTXs[0]->address,
                    self->arm64_relocator.relocator_insnCTXs[i].relocated_insnCTXs_count);
        }
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }

    free(codeslice);
    return;
}

void TrampolineBuildForLeave(InterceptorBackend *self, HookEntry *entry) {
    ARM64HookEntryBackend *entry_backend = (ARM64HookEntryBackend *)entry->backend;
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
    char temp_codeslice[256]             = {0};
    CodeSlice *codeslice                 = NULL;
    ARM64HookEntryBackend *entry_backend = (ARM64HookEntryBackend *)entry->backend;
    RetStatus status                     = RS_SUCCESS;
    zz_addr_t target_addr                = (zz_addr_t)entry->target_ptr;
    ARM64AssemblyrWriter *arm64_writer;

    arm64_writer = &self->arm64_writer;
    arm64_writer_reset(arm64_writer, ALIGN_CEIL(temp_codeslice, 4), target_addr);

    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
        if (entry_backend->redirect_code_size == ARM64_TINY_REDIRECT_SIZE) {
            arm64_writer_put_b_imm(arm64_writer,
                                   (zz_addr_t)entry->on_enter_transfer_trampoline - (zz_addr_t)arm64_writer->start_pc);
        } else {
            arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17,
                                                (zz_addr_t)entry->on_enter_transfer_trampoline);
        }
    } else {
        if (entry_backend->redirect_code_size == ARM64_TINY_REDIRECT_SIZE) {
            arm64_writer_put_b_imm(arm64_writer,
                                   (zz_addr_t)entry->on_enter_transfer_trampoline - (zz_addr_t)arm64_writer->start_pc);
        } else {
            arm64_writer_put_ldr_br_reg_address(arm64_writer, ARM64_REG_X17, (zz_addr_t)entry->on_enter_trampoline);
        }
    }

    if (!MemoryHelperPatchCode((zz_addr_t)target_addr, (zz_ptr_t)arm64_writer->insns_buffer, arm64_writer->insns_size))
        status = RS_FAILED;

    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= Trampoline Summary ======= \n");
        sprintf(buffer + strlen(buffer), "\tHookZz Target Address: %p\n", entry->target_ptr);

        sprintf(buffer + strlen(buffer), "\tHookZz Target Address Arch Mode: ARM64\n");
        if (entry_backend->redirect_code_size == ARM64_TINY_REDIRECT_SIZE) {
            sprintf(buffer + strlen(buffer), "\tARM64 Jump Type: Near Jump(B xxx)\n");
        } else if (entry_backend->redirect_code_size == ARM64_FULL_REDIRECT_SIZE) {
            sprintf(buffer + strlen(buffer), "\tARM64 Brach Jump Type: Abs Jump(ldr r17, #4; .long address)\n");
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

#if 0

#include "MachoKit/macho_kit.h"
#include <mach-o/dyld.h>

typedef struct _InterceptorBackendNoJB {
    void *enter_bridge; // hardcode
    void *leave_bridge; // hardcode
    unsigned long num_of_entry;
    unsigned long code_seg_offset;
    unsigned long data_seg_offset;
} InterceptorBackendNoJB;

typedef struct _HookEntryNoJB {
    void *target_fileoff;
    unsigned long is_near_jump;
    void *entry_address;
    void *on_enter_trampoline;  // HookZzData, 99% hardcode
    void *on_invoke_trampoline; // HookZzData, fixed instructions
    void *on_leave_trampoline;  // HookZzData, 99% hardcode
} HookEntryNoJB;

RetStatus ZzActivateStaticBinaryInstrumentationTrampoline(HookEntry *entry, zz_addr_t target_fileoff) {
    struct mach_header_64 *header           = (struct mach_header_64 *)_dyld_get_image_header(0);
    struct segment_command_64 *text_seg_cmd = zz_macho_get_segment_64_via_name(header, "__TEXT");
    struct segment_command_64 *data_seg_cmd = zz_macho_get_segment_64_via_name(header, "HookZzData");
    zz_addr_t aslr_slide                    = (zz_addr_t)header - text_seg_cmd->vmaddr;
    InterceptorBackendNoJB *nojb_backend    = (InterceptorBackendNoJB *)(aslr_slide + data_seg_cmd->vmaddr);
    nojb_backend->enter_bridge              = (void *)enter_bridge_template;
    nojb_backend->leave_bridge              = (void *)leave_bridge_template;

    HookEntryNoJB *nojb_entry = (HookEntryNoJB *)(data_seg_cmd->vmaddr + sizeof(HookEntryNoJB) + aslr_slide);
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
    return RS_SUCCESS;
}
#endif
