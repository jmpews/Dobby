#include "thunker-arm.h"
#include "backend-arm-helper.h"

// 前提: arm 可以直接访问 pc 寄存器, 也就是说无需中间寄存器就可以实现 `abs
// jump`.

// frida-gum 的做法, 手动恢复 lr, 并将 `next_hop` 写在之前 store `lr` 的位置,
// 之后利用恢复寄存器跳转

// 还有一个点, 就是 hook-entry 的参数传递, 这就是为啥 frida-gum 中为啥把
// gum_emit_prolog 分成了两部分, 把 gum_emit_push_cpu_context_high_part 放在 x7
// 用之前.

// 这个和 arm64 有不同, arm64 中借助了一个中间寄存器 x16 or x17.

// 重点是在: 1. 在 restore 之前完成所有工作 2. 利用 restore 过程修改 pc.

// 当然也有其他做法, 比如最后一个操作是 ldr pc, [sp, #?], 也没啥问题.

// 14 = 5 + 8 + 1

// 按理说应该最先进入 ctx_save, 之后才能保证即使各种操作寄存器不被污染,
// 几个理想方案 1. 把 ctx_save 归属为 trampoline, 优点: 优先进行寄存器状态保存,
// 缺点: ctx_save 重复多次 2. 把 ctx_save 归属为 thunk, 统一做寄存器保存,
// trampline 入口处进行参数保存至栈. 优点: ctx_save 可以作为公用. 缺点:
// 操作复杂, 耦合略强. 3. 把 ctx_save 进行拆分, 缺点: 模块化设计差, 耦合强
// (frida-gum采用)

__attribute__((__naked__)) void ctx_save() {
    __asm__ volatile(".arm\n"
                     "sub sp, sp, #(14*4)\n"

                     "str lr, [sp, #(13*4)]\n"

                     "str r12, [sp, #(12*4)]\n"
                     "str r11, [sp, #(11*4)]\n"
                     "str r10, [sp, #(10*4)]\n"
                     "str r9, [sp, #(9*4)]\n"
                     "str r8, [sp, #(8*4)]\n"

                     "str r7, [sp, #(7*4)]\n"
                     "str r6, [sp, #(6*4)]\n"
                     "str r5, [sp, #(5*4)]\n"
                     "str r4, [sp, #(4*4)]\n"
                     "str r3, [sp, #(3*4)]\n"
                     "str r2, [sp, #(2*4)]\n"
                     "str r1, [sp, #(1*4)]\n"
                     "str r0, [sp, #(0*4)]\n");
}

__attribute__((__naked__)) void ctx_restore() {
    __asm__ volatile(".arm\n"
                     "ldr r0, [sp], #4\n"
                     "ldr r1, [sp], #4\n"
                     "ldr r2, [sp], #4\n"
                     "ldr r3, [sp], #4\n"
                     "ldr r4, [sp], #4\n"
                     "ldr r5, [sp], #4\n"
                     "ldr r6, [sp], #4\n"
                     "ldr r7, [sp], #4\n"

                     "ldr r8, [sp], #4\n"
                     "ldr r9, [sp], #4\n"
                     "ldr r10, [sp], #4\n"
                     "ldr r11, [sp], #4\n"
                     "ldr r12, [sp], #4\n"

                     "ldr lr, [sp], #4\n");
}

// just like pre_call, wow!
void function_context_begin_invocation(ZzHookFunctionEntry *entry, zz_ptr_t next_hop, RegState *rs,
                                       zz_ptr_t caller_ret_addr) {

    ZZ_DEBUG_LOG("target %p call begin-invocation", entry->target_ptr);

    ZzThreadStack *threadstack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if (!threadstack) {
        threadstack = ZzNewThreadStack(entry->thread_local_key);
    }
    ZzCallStack *callstack = ZzNewCallStack();
    ZzPushCallStack(threadstack, callstack);

    /* call pre_call */
    if (entry->pre_call) {
        PRECALL pre_call;
        HookEntryInfo entry_info;
        entry_info.hook_id      = entry->id;
        entry_info.hook_address = entry->target_ptr;
        pre_call                = entry->pre_call;
        (*pre_call)(rs, (ThreadStack *)threadstack, (CallStack *)callstack, (const HookEntryInfo *)&entry_info);
    }

    /* set next hop */
    if (entry->replace_call) {
        *(zz_ptr_t *)next_hop = entry->replace_call;
    } else {
        *(zz_ptr_t *)next_hop = entry->on_invoke_trampoline;
    }

    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
        callstack->caller_ret_addr   = *(zz_ptr_t *)caller_ret_addr;
        *(zz_ptr_t *)caller_ret_addr = entry->on_leave_trampoline;
    }

}

void insn_context_end_invocation(ZzHookFunctionEntry *entry, zz_ptr_t next_hop, RegState *rs,
                                      zz_ptr_t caller_ret_addr) {
    ZZ_DEBUG_LOG("target %p insn_context__end_invocation", entry->target_ptr);

    ZzThreadStack *threadstack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if (!threadstack) {
#if defined(DEBUG_MODE)
        debug_break();
#endif
    }
    ZzCallStack *callstack = ZzPopCallStack(threadstack);

    if (entry->post_call) {
        POSTCALL post_call;
        HookEntryInfo entry_info;
        entry_info.hook_id      = entry->id;
        entry_info.hook_address = entry->target_ptr;
        post_call               = entry->post_call;
        (*post_call)(rs, (ThreadStack *)threadstack, (CallStack *)callstack, (const HookEntryInfo *)&entry_info);
    }

    // set next hop
    *(zz_ptr_t *)next_hop = (zz_ptr_t)entry->next_insn_addr;

    ZzFreeCallStack(callstack);
}

void dynamic_binary_instrumentation_invocation(ZzHookFunctionEntry *entry, zz_ptr_t next_hop, RegState *rs) {

    /* call pre_call */
    if (entry->pre_call) {
        STUBCALL pre_call;
        HookEntryInfo entry_info;
        entry_info.hook_id      = entry->id;
        entry_info.hook_address = entry->target_ptr;
        pre_call                = entry->stub_call;
        (*pre_call)(rs, (const HookEntryInfo *)&entry_info);
    }


    *(zz_ptr_t *)next_hop = entry->on_invoke_trampoline;
}

// just like post_call, wow!
void function_context_end_invocation(ZzHookFunctionEntry *entry, zz_ptr_t next_hop, RegState *rs) {
    ZZ_DEBUG_LOG("%p call end-invocation", entry->target_ptr);

    ZzThreadStack *threadstack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if (!threadstack) {
#if defined(DEBUG_MODE)
        debug_break();
#endif
    }
    ZzCallStack *callstack = ZzPopCallStack(threadstack);

    if (entry->post_call) {
        POSTCALL post_call;
        HookEntryInfo entry_info;
        entry_info.hook_id      = entry->id;
        entry_info.hook_address = entry->target_ptr;
        post_call               = entry->post_call;
        (*post_call)(rs, (ThreadStack *)threadstack, (CallStack *)callstack, (const HookEntryInfo *)&entry_info);
    }

    // set next hop
    *(zz_ptr_t *)next_hop = callstack->caller_ret_addr;

    ZzFreeCallStack(callstack);
}

void zz_thumb_thunker_build_enter_thunk(ZzThumbAssemblerWriter *writer) {

    // save general registers and sp
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_save), 15 * 4);
    zz_arm_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_PC, 1);
    zz_arm_writer_put_bx_reg(writer, ZZ_ARM_REG_R1);

    zz_thumb_writer_put_sub_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x8);
    zz_thumb_writer_put_str_reg_reg_offset(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);

    // pass func args
    // entry
    zz_thumb_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM_REG_R0, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8);
    // next hop
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x4);
    // RegState
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R2, ZZ_ARM_REG_SP, 0x4);
    // caller ret address
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R3, ZZ_ARM_REG_SP, 0x8 + 13 * 4);

    // call function_context_begin_invocation
    zz_thumb_writer_put_ldr_b_reg_address(writer, ZZ_ARM_REG_LR, (zz_addr_t)function_context_begin_invocation);
    zz_thumb_writer_put_blx_reg(writer, ZZ_ARM_REG_LR);

    // restore general registers and sp
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_restore), 14 * 4);
    zz_arm_writer_put_bx_to_thumb(writer);

    // restore arg space
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x4);

    // pop and jump to next hop
    // use Post-indexed ldr to `pop`
    zz_thumb_writer_put_ldr_index_reg_reg_offset(writer, ZZ_ARM_REG_PC, ZZ_ARM_REG_SP, 4, 0);
}

void zz_thumb_thunker_build_insn_leave_thunk(ZzThumbAssemblerWriter *writer) {

    // save general registers and sp
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_save), 15 * 4);
    zz_arm_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_PC, 1);
    zz_arm_writer_put_bx_reg(writer, ZZ_ARM_REG_R1);

    zz_thumb_writer_put_sub_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x8);
    zz_thumb_writer_put_str_reg_reg_offset(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);

    // pass enter func args
    // entry
    zz_thumb_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM_REG_R0, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8);
    // next hop
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x4);
    // RegState
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R2, ZZ_ARM_REG_SP, 0x4);
    // caller ret address
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R3, ZZ_ARM_REG_SP, 0x8 + 13 * 4);

    // call function_context_half_invocation
    zz_thumb_writer_put_ldr_b_reg_address(writer, ZZ_ARM_REG_LR, (zz_addr_t)insn_context_end_invocation);
    zz_thumb_writer_put_blx_reg(writer, ZZ_ARM_REG_LR);

    // restore general registers and sp
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_restore), 14 * 4);
    zz_arm_writer_put_bx_to_thumb(writer);

    // restore arg space
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x4);

    // pop and jump to next hop
    // use Post-indexed ldr to `pop`
    zz_thumb_writer_put_ldr_index_reg_reg_offset(writer, ZZ_ARM_REG_PC, ZZ_ARM_REG_SP, 4, 0);
}

void zz_thumb_thunker_build_dynamic_binary_instrumentation_thunk(ZzThumbAssemblerWriter *writer) {

    // save general registers and sp
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_save), 15 * 4);
    zz_arm_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_PC, 1);
    zz_arm_writer_put_bx_reg(writer, ZZ_ARM_REG_R1);

    zz_thumb_writer_put_sub_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x8);
    zz_thumb_writer_put_str_reg_reg_offset(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);

    // pass enter func args
    // entry
    zz_thumb_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM_REG_R0, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8);
    // next hop
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x4);
    // RegState
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R2, ZZ_ARM_REG_SP, 0x4);
    // caller ret address
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R3, ZZ_ARM_REG_SP, 0x8 + 13 * 4);

    // call function_context_half_invocation
    zz_thumb_writer_put_ldr_b_reg_address(writer, ZZ_ARM_REG_LR, (zz_addr_t)dynamic_binary_instrumentation_invocation);
    zz_thumb_writer_put_blx_reg(writer, ZZ_ARM_REG_LR);

    // restore general registers and sp
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_restore), 14 * 4);
    zz_arm_writer_put_bx_to_thumb(writer);

    // restore arg space
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x4);

    // pop and jump to next hop
    // use Post-indexed ldr to `pop`
    zz_thumb_writer_put_ldr_index_reg_reg_offset(writer, ZZ_ARM_REG_PC, ZZ_ARM_REG_SP, 4, 0);
}

void zz_thumb_thunker_build_leave_thunk(ZzThumbAssemblerWriter *writer) {

    // save general registers and sp
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_save), 15 * 4);
    zz_arm_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_PC, 1);
    zz_arm_writer_put_bx_reg(writer, ZZ_ARM_REG_R1);

    zz_thumb_writer_put_sub_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x8);
    zz_thumb_writer_put_str_reg_reg_offset(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, 0x4);

    // pass enter func args
    // entry
    zz_thumb_writer_put_ldr_reg_reg_offset(writer, ZZ_ARM_REG_R0, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8);
    // next hop
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R1, ZZ_ARM_REG_SP, CTX_SAVE_STACK_OFFSET + 0x8 + 0x4);
    // RegState
    zz_thumb_writer_put_add_reg_reg_imm(writer, ZZ_ARM_REG_R2, ZZ_ARM_REG_SP, 0x4);

    // call function_context_begin_invocation
    zz_thumb_writer_put_ldr_b_reg_address(writer, ZZ_ARM_REG_LR, (zz_addr_t)function_context_end_invocation);
    zz_thumb_writer_put_blx_reg(writer, ZZ_ARM_REG_LR);

    // restore general registers and sp
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x8);
    zz_thumb_writer_put_bx_reg(writer, ZZ_ARM_REG_PC);
    zz_arm_writer_put_bytes(writer, THUMB_FUNCTION_ADDRESS((void *)ctx_restore), 14 * 4);
    zz_arm_writer_put_bx_to_thumb(writer);

    // restore arg space
    zz_thumb_writer_put_add_reg_imm(writer, ZZ_ARM_REG_SP, 0x4);

    // pop and jump to next hop
    // use Post-indexed ldr to `pop`
    zz_thumb_writer_put_ldr_index_reg_reg_offset(writer, ZZ_ARM_REG_PC, ZZ_ARM_REG_SP, 4, 0);
}

ZZSTATUS ZzThunkerBuildThunk(ZzInterceptorBackend *self) {
    char temp_code_slice[512]       = {0};
    ZzThumbAssemblerWriter *thumb_writer = NULL;
    ZzCodeSlice *code_slice              = NULL;
    ZZSTATUS status                      = ZZ_SUCCESS;

    thumb_writer = &self->thumb_writer;

    // buid enter_thunk
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);
    zz_thumb_thunker_build_enter_thunk(thumb_writer);
    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);

    if (code_slice)
        self->enter_thunk = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[2048]       = {};
        char thunk_buffer[2048] = {};
        int t                   = 0;
        sprintf(buffer + strlen(buffer), "%s\n", "ZzThunkerBuildThunk:");
        for (zz_addr_t  p = thumb_writer->w_start_address; p < thumb_writer->w_start_address + thumb_writer->size; p++, t = t + 5) {
            sprintf(thunk_buffer + t, "0x%.2x ", *(unsigned char *)p);
        }
        HookZzDebugInfoLog("%s", thunk_buffer);
        sprintf(buffer + strlen(buffer), "LogInfo: enter_thunk at %p, length: %ld.\n", code_slice->data,
                code_slice->size);
        HookZzDebugInfoLog("%s", buffer);
    }

    // build leave_thunk
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);
    zz_thumb_thunker_build_leave_thunk(thumb_writer);

    // code patch
    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
    if (code_slice)
        self->leave_thunk = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[2048]       = {};
        char thunk_buffer[2048] = {};
        int t                   = 0;
        sprintf(buffer + strlen(buffer), "%s\n", "ZzThunkerBuildThunk:");
        for (zz_addr_t p = thumb_writer->w_start_address; p < thumb_writer->w_start_address + thumb_writer->size; p++, t = t + 5) {
            sprintf(thunk_buffer + t, "0x%.2x ", *(unsigned char *)p);
        }
        HookZzDebugInfoLog("%s", thunk_buffer);
        sprintf(buffer + strlen(buffer), "LogInfo: leave_thunk at %p, length: %ld.\n", code_slice->data,
                code_slice->size);
        HookZzDebugInfoLog("%s", buffer);
    }

    // build insn leave thunk
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);
    zz_thumb_thunker_build_insn_leave_thunk(thumb_writer);

    // code patch
    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
    if (code_slice)
        self->insn_leave_thunk = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[2048]       = {};
        char thunk_buffer[2048] = {};
        int t                   = 0;
        sprintf(buffer + strlen(buffer), "%s\n", "ZzThunkerBuildThunk:");
        for (zz_addr_t p = thumb_writer->w_start_address; p < thumb_writer->w_start_address + thumb_writer->size; p++, t = t + 5) {
            sprintf(thunk_buffer + t, "0x%.2x ", *(unsigned char *)p);
        }
        HookZzDebugInfoLog("%s", thunk_buffer);
        sprintf(buffer + strlen(buffer), "LogInfo: insn_leave_thunk at %p, length: %ld.\n", code_slice->data,
                code_slice->size);
        HookZzDebugInfoLog("%s", buffer);
    }

    // build dynamic_binary_instrumentation_thunk
    zz_thumb_writer_reset(thumb_writer, temp_code_slice, 0);
    zz_thumb_thunker_build_dynamic_binary_instrumentation_thunk(thumb_writer);

    // code patch
    code_slice = zz_thumb_code_patch(thumb_writer, self->allocator, 0, 0);
    if (code_slice)
        self->dynamic_binary_instrumentation_thunk = code_slice->data + 1;
    else
        return ZZ_FAILED;

    // debug log
    if (HookZzDebugInfoIsEnable()) {
        char buffer[2048]       = {};
        char thunk_buffer[2048] = {};
        int t                   = 0;
        sprintf(buffer + strlen(buffer), "%s\n", "ZzThunkerBuildThunk:");
        for (zz_addr_t p = thumb_writer->w_start_address; p < thumb_writer->w_start_address + thumb_writer->size; p++, t = t + 5) {
            sprintf(thunk_buffer + t, "0x%.2x ", *(unsigned char *)p);
        }
        HookZzDebugInfoLog("%s", thunk_buffer);
        sprintf(buffer + strlen(buffer), "LogInfo: dynamic_binary_instrumentation_thunk at %p, length: %ld.\n", code_slice->data,
                code_slice->size);
        HookZzDebugInfoLog("%s", buffer);
    }
    return status;
}
