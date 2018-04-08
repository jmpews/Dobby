#include "closure-bridge-arm64.h"
#include "backend-arm64-helper.h"
#include <string.h>

#include <CommonKit/log/log_kit.h>

#include <sys/mman.h>
#include <unistd.h>

#define closure_bridge_trampoline_template_length (7 * 4)

static ClosureBridgeTrampolineTable *gClosureBridageTrampolineTable;

void common_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {

    USER_CODE_CALL userCodeCall = cbd->user_code;
    printf("CommonBridgeHandler:");
    printf("\tTrampoline Address: %p", cbd->redirect_trampoline);
    userCodeCall(rs, cbd);
    // set return address
    rs->general.x[17] = rs->general.x[17];
    return;
}

static ClosureBridgeTrampolineTable *ClosureBridgeTrampolineTableAllocate(void) {
    void *mmap_page;
    long page_size;
    page_size = sysconf(_SC_PAGESIZE);

    mmap_page = mmap(0, 1, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (mmap_page == MAP_FAILED) {
        ZZ_COMMON_ERROR_LOG();
        return NULL;
    }

    if (mprotect(mmap_page, (size_t) page_size, (PROT_WRITE | PROT_READ | PROT_EXEC))) {
        ZZ_COMMON_ERROR_LOG();
        return NULL;
    }

    int t = page_size / closure_bridge_trampoline_template_length;
    void *copy_address = mmap_page;
    for (int i = 0; i < t; ++i) {
        copy_address = (void *) ((intptr_t) mmap_page +
                                 i * closure_bridge_trampoline_template_length);
        memcpy(copy_address, closure_bridge_trampoline_template,
               closure_bridge_trampoline_template_length);
    }

    ClosureBridgeTrampolineTable *table = (ClosureBridgeTrampolineTable *) malloc(
            sizeof(ClosureBridgeTrampolineTable));
    table->entry = mmap_page;
    table->trampoline_page = mmap_page;
    table->used_count = 0;
    table->free_count = (uint16_t) t;
    return table;
}


static void ClosureBridgeTrampolineTableFree(ClosureBridgeTrampolineTable *table) {
    return;
}

ClosureBridgeData *ClosureBridgeAllocate(void *user_data, void *user_code) {
    ClosureBridgeTrampolineTable *table = gClosureBridageTrampolineTable;
    if (table == NULL || table->free_count == 0) {
        table = ClosureBridgeTrampolineTableAllocate();
        if (table == NULL)
            return NULL;

        table->next = gClosureBridageTrampolineTable;
        if (table->next != NULL) {
            table->next->prev = table;
        }
        gClosureBridageTrampolineTable = table;
    }

    ClosureBridgeData *bridgeData = (ClosureBridgeData *) malloc(sizeof(ClosureBridgeData));
    bridgeData->common_bridge_handler = (void *) common_bridge_handler;

    bridgeData->user_code = user_code;
    bridgeData->user_data = user_data;
    uint16_t trampoline_used_count = gClosureBridageTrampolineTable->used_count;
    bridgeData->redirect_trampoline = (void *) (
            (intptr_t) gClosureBridageTrampolineTable->trampoline_page +
            closure_bridge_trampoline_template_length * trampoline_used_count);

    // bind data to trampline
    void *tmp = (void *) ((intptr_t) bridgeData->redirect_trampoline + 4 * 3);
    memcpy(tmp, &bridgeData, sizeof(ClosureBridgeData *));

    // set trampoline to bridge
    void *tmpX = (void *) closure_bridge_template;
    tmp = (void *) ((intptr_t) bridgeData->redirect_trampoline + 4 * 5);
    memcpy(tmp, &tmpX, sizeof(void *));

    table->used_count++;
    table->free_count--;

    return bridgeData;
}

static void ClosureBridgeFree(ClosureBridgeData *bridgeData) {
    return;
}





//
//
//
//void insn_context_end_invocation(HookEntry *entry, zz_ptr_t nextHop, RegState *rs,
//                                 zz_ptr_t retAddr) {
//    ZZ_DEBUG_LOG("target %p insn_context__end_invocation", entry->target_ptr);
//
//    ThreadStack *threadstack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
//    if (!threadstack) {
//#if defined(DEBUG_MODE)
//        debug_break();
//#endif
//    }
//    CallStack *callstack = ThreadStackPopCallStack(threadstack);
//
//    if (entry->post_call) {
//        POSTCALL post_call;
//        HookEntryInfo entryInfo;
//        entryInfo.hook_id = entry->id;
//        entryInfo.hook_address = entry->target_ptr;
//        post_call = entry->post_call;
//        (*post_call)(rs, (ThreadStack *) threadstack, (CallStack *) callstack,
//                     (const HookEntryInfo *) &entryInfo);
//    }
//
//    // set next hop
//    *(zz_ptr_t *) nextHop = (zz_ptr_t) entry->next_insn_addr;
//
//    CallStackFree(callstack);
//}
//
//void dynamic_binary_instrumentation_invocation(HookEntry *entry, zz_ptr_t nextHop, RegState *rs) {
//
//    /* call pre_call */
//    if (entry->stub_call) {
//        STUBCALL stub_call;
//        HookEntryInfo entryInfo;
//        entryInfo.hook_id = entry->id;
//        entryInfo.hook_address = entry->target_ptr;
//        stub_call = entry->stub_call;
//        (*stub_call)(rs, (const HookEntryInfo *) &entryInfo);
//    }
//
//    *(zz_ptr_t *) nextHop = entry->on_invoke_trampoline;
//}
//
//
//
//void arm64_bridge_build_enter_bridge(ARM64AssemblerWriter *writer) {
//    // save general registers and sp
//    arm64_writer_put_bytes(writer, (void *) ctx_save, 23 * 4);
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     8 + CTX_SAVE_STACK_OFFSET + 2 * 8);
//
//    // trick: use the `ctx_save` left [sp]
//    arm64_writer_put_str_reg_reg_offset(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP, 0 * 8);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_sub_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    // pass enter func args
//    // entry
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X0, ZZ_ARM64_REG_SP,
//                                        2 * 8 + 8 + CTX_SAVE_STACK_OFFSET);
//    // next hop
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     2 * 8 + 8 + CTX_SAVE_STACK_OFFSET + 0x8);
//    // RegState
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X2, ZZ_ARM64_REG_SP, 2 * 8);
//    // caller ret address
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X3, ZZ_ARM64_REG_SP,
//                                     2 * 8 + 2 * 8 + 28 * 8 + 8);
//
//    // call function_context_begin_invocation
//    arm64_writer_put_ldr_blr_b_reg_address(writer, ZZ_ARM64_REG_X17,
//                                           (zz_addr_t) function_context_begin_invocation);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* restore general registers threadstack */
//    arm64_writer_put_bytes(writer, (void *) ctx_restore, 21 * 4);
//
//    /* load next hop to x17 */
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x8);
//
//    /* restore next hop and arg threadstack */
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* jump to next hop */
//    arm64_writer_put_br_reg(writer, ZZ_ARM64_REG_X17);
//}
//
//void arm64_bridge_build_insn_leave_bridge(ARM64AssemblerWriter *writer) {
//    // save general registers and sp
//    arm64_writer_put_bytes(writer, (void *) ctx_save, 23 * 4);
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     8 + CTX_SAVE_STACK_OFFSET + 2 * 8);
//
//    // trick: use the `ctx_save` left [sp]
//    arm64_writer_put_str_reg_reg_offset(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP, 0 * 8);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_sub_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    // pass enter func args
//    // entry
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X0, ZZ_ARM64_REG_SP,
//                                        2 * 8 + 8 + CTX_SAVE_STACK_OFFSET);
//    // next hop
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     2 * 8 + 8 + CTX_SAVE_STACK_OFFSET + 0x8);
//
//    // RegState
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X2, ZZ_ARM64_REG_SP, 2 * 8);
//    // caller ret address
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X3, ZZ_ARM64_REG_SP,
//                                     2 * 8 + 2 * 8 + 28 * 8 + 8);
//
//    // call function_context_half_invocation
//    arm64_writer_put_ldr_blr_b_reg_address(writer, ZZ_ARM64_REG_X17,
//                                           (zz_addr_t) insn_context_end_invocation);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* restore general registers threadstack */
//    arm64_writer_put_bytes(writer, (void *) ctx_restore, 21 * 4);
//
//    /* load next hop to x17 */
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x8);
//
//    /* restore next hop and arg threadstack */
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* jump to next hop */
//    arm64_writer_put_br_reg(writer, ZZ_ARM64_REG_X17);
//}
//
//void arm64_bridge_build_leave_bridge(ARM64AssemblerWriter *writer) {
//    // save general registers and sp
//    arm64_writer_put_bytes(writer, (void *) ctx_save, 23 * 4);
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     8 + CTX_SAVE_STACK_OFFSET + 2 * 8);
//
//    // trick: use the `ctx_save` left [sp]
//    arm64_writer_put_str_reg_reg_offset(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP, 0 * 8);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_sub_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    // pass enter func args
//    /* 1. entry */
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X0, ZZ_ARM64_REG_SP,
//                                        2 * 8 + 8 + CTX_SAVE_STACK_OFFSET);
//    /* 2. next hop*/
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     2 * 8 + 8 + CTX_SAVE_STACK_OFFSET + 0x8);
//
//    // RegState
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X2, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* call function_context_end_invocation */
//    arm64_writer_put_ldr_blr_b_reg_address(writer, ZZ_ARM64_REG_X17,
//                                           (zz_addr_t) function_context_end_invocation);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* restore general registers threadstack */
//    arm64_writer_put_bytes(writer, (void *) ctx_restore, 21 * 4);
//
//    /* load next hop to x17 */
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x8);
//
//    /* restore next hop and arg threadstack */
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* jump to next hop */
//    arm64_writer_put_br_reg(writer, ZZ_ARM64_REG_X17);
//}
//
//void arm64_bridge_build_dynamic_binary_instrumentation_bridge(ARM64AssemblerWriter *writer) {
//    // save general registers and sp
//    arm64_writer_put_bytes(writer, (void *) ctx_save, 23 * 4);
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     8 + CTX_SAVE_STACK_OFFSET + 2 * 8);
//
//    // trick: use the `ctx_save` left [sp]
//    arm64_writer_put_str_reg_reg_offset(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP, 0 * 8);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_sub_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    // pass enter func args
//    // entry
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X0, ZZ_ARM64_REG_SP,
//                                        2 * 8 + 8 + CTX_SAVE_STACK_OFFSET);
//    // next hop
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X1, ZZ_ARM64_REG_SP,
//                                     2 * 8 + 8 + CTX_SAVE_STACK_OFFSET + 0x8);
//    // RegState
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X2, ZZ_ARM64_REG_SP, 2 * 8);
//    // caller ret address
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_X3, ZZ_ARM64_REG_SP,
//                                     2 * 8 + 2 * 8 + 28 * 8 + 8);
//
//    // call function_context_begin_invocation
//    arm64_writer_put_ldr_blr_b_reg_address(writer, ZZ_ARM64_REG_X17,
//                                           (zz_addr_t) dynamic_binary_instrumentation_invocation);
//
//    // alignment padding + dummy PC
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* restore general registers threadstack */
//    arm64_writer_put_bytes(writer, (void *) ctx_restore, 21 * 4);
//
//    /* load next hop to x17 */
//    arm64_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM64_REG_X17, ZZ_ARM64_REG_SP, 0x8);
//
//    /* restore next hop and arg threadstack */
//    arm64_writer_put_add_reg_reg_imm(writer, ZZ_ARM64_REG_SP, ZZ_ARM64_REG_SP, 2 * 8);
//
//    /* jump to next hop */
//    arm64_writer_put_br_reg(writer, ZZ_ARM64_REG_X17);
//}
//
//void BridgeBuildAll(InterceptorBackend *self) {
//    char temp_codeslice[512] = {0};
//    ARM64AssemblerWriter *arm64_writer = NULL;
//    CodeSlice *codeslice = NULL;
//    RetStatus status = RS_SUCCESS;
//
//    arm64_writer = &self->arm64_writer;
//
//    /* build enter_bridge */
//    arm64_writer_reset(arm64_writer, temp_codeslice, 0);
//    arm64_bridge_build_enter_bridge(arm64_writer);
//
//    /* code patch */
//    codeslice = arm64_code_patch(arm64_writer, self->emm, 0, 0);
//    if (codeslice)
//        self->enter_bridge = (void *) enter_bridge_template;
//        // self->enter_bridge = codeslice->data;
//    else
//        return RS_FAILED;
//
//    /* debug log */
//    if (DebugLogControlerIsEnableLog()) {
//        char buffer[1024] = {};
//        sprintf(buffer + strlen(buffer), "%s\n", "BridgeBuildAll:");
//        sprintf(buffer + strlen(buffer),
//                "LogInfo: enter_bridge at %p, use enter_bridge_template.\n",
//                (void *) enter_bridge_template);
//        // sprintf(buffer + strlen(buffer), "LogInfo: enter_bridge at %p, length: %ld.\n", codeslice->data,
//        // codeslice->size);
//        DEBUG_LOG("%s", buffer);
//    }
//
//    /* build leave_bridge */
//    arm64_writer_reset(arm64_writer, temp_codeslice, 0);
//    arm64_bridge_build_leave_bridge(arm64_writer);
//
//    /* code patch */
//    codeslice = arm64_code_patch(arm64_writer, self->emm, 0, 0);
//    if (codeslice)
//        self->leave_bridge = codeslice->data;
//    else
//        return RS_FAILED;
//
//    /* debug log */
//    if (DebugLogControlerIsEnableLog()) {
//        char buffer[1024] = {};
//        sprintf(buffer + strlen(buffer), "%s\n", "BridgeBuildAll:");
//        sprintf(buffer + strlen(buffer), "LogInfo: leave_bridge at %p, length: %ld.\n",
//                codeslice->data,
//                codeslice->size);
//        DEBUG_LOG("%s", buffer);
//    }
//
//    /* build insn_leave_bridge */
//    arm64_writer_reset(arm64_writer, temp_codeslice, 0);
//    arm64_bridge_build_insn_leave_bridge(arm64_writer);
//
//    /* code patch */
//    codeslice = arm64_code_patch(arm64_writer, self->emm, 0, 0);
//    if (codeslice)
//        self->insn_leave_bridge = codeslice->data;
//    else
//        return RS_FAILED;
//
//    /* debug log */
//    if (DebugLogControlerIsEnableLog()) {
//        char buffer[1024] = {};
//        sprintf(buffer + strlen(buffer), "%s\n", "BridgeBuildAll:");
//        sprintf(buffer + strlen(buffer), "LogInfo: insn_leave_bridge at %p, length: %ld.\n",
//                codeslice->data,
//                codeslice->size);
//        DEBUG_LOG("%s", buffer);
//    }
//
//    /* build dynamic_binary_instrumentation_bridge */
//    arm64_writer_reset(arm64_writer, temp_codeslice, 0);
//    arm64_bridge_build_dynamic_binary_instrumentation_bridge(arm64_writer);
//
//    /* code patch */
//    codeslice = arm64_code_patch(arm64_writer, self->emm, 0, 0);
//    if (codeslice)
//        self->dynamic_binary_instrumentation_bridge = codeslice->data;
//    else
//        return RS_FAILED;
//
//    /* debug log */
//    if (DebugLogControlerIsEnableLog()) {
//        char buffer[1024] = {};
//        sprintf(buffer + strlen(buffer), "%s\n", "BridgeBuildAll:");
//        sprintf(buffer + strlen(buffer),
//                "LogInfo: dynamic_binary_instrumentation_bridge at %p, length: %ld.\n",
//                codeslice->data, codeslice->size);
//        DEBUG_LOG("%s", buffer);
//    }
//
//    return status;
//}
