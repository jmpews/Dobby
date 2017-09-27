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

#include "thunker-arm64.h"

/*
    Programmer’s Guide for ARMv8-A:
        Page: (6-15)
        Page: (6-16)

    STP X9, X8, [X4]
        Stores the doubleword in X9 to address X4 and stores the doubleword
   in X8 to address X4 + 8. LDP X8, X2, [X0, #0x10]! Loads doubleword at
   address X0 + 0x10 into X8 and the doubleword at address X0 + 0x10 + 8
   into X2 and add 0x10 to X0. See Figure 6-7.
 */

// 前提: 不能直接访问 pc, 也就说只有通过寄存器才能实现绝对地址跳

__attribute__((__naked__)) static void ctx_save() {
    __asm__ volatile(

        /* save {q0-q7} */
        "sub sp, sp, #(8*16)\n"
        "stp q6, q7, [sp, #(6*16)]\n"
        "stp q4, q5, [sp, #(4*16)]\n"
        "stp q2, q3, [sp, #(2*16)]\n"
        "stp q0, q1, [sp, #(0*16)]\n"

        /* save {x1-x30} */
        "sub sp, sp, #(30*8)\n"
        "stp fp, lr, [sp, #(28*8)]\n"
        "stp x27, x28, [sp, #(26*8)]\n"
        "stp x25, x26, [sp, #(24*8)]\n"
        "stp x23, x24, [sp, #(22*8)]\n"
        "stp x21, x22, [sp, #(20*8)]\n"
        "stp x19, x20, [sp, #(18*8)]\n"
        "stp x17, x18, [sp, #(16*8)]\n"
        "stp x15, x16, [sp, #(14*8)]\n"
        "stp x13, x14, [sp, #(12*8)]\n"
        "stp x11, x12, [sp, #(10*8)]\n"
        "stp x9, x10, [sp, #(8*8)]\n"
        "stp x7, x8, [sp, #(6*8)]\n"
        "stp x5, x6, [sp, #(4*8)]\n"
        "stp x3, x4, [sp, #(2*8)]\n"
        "stp x1, x2, [sp, #(0*8)]\n"

        "sub sp, sp, #(1*8)\n"
        "str x0, [sp, #(0*8)]\n");
}

__attribute__((__naked__)) static void pass_enter_func_args() {}

__attribute__((__naked__)) static void pass_half_func_args() {}

__attribute__((__naked__)) static void pass_leave_func_args() {}

__attribute__((__naked__)) static void ctx_restore() {
    __asm__ volatile(
        /* restore x0 */
        "ldr x0, [sp], #8\n"

        /* restore {x1-x30} */
        "ldp x1, x2, [sp], #16\n"
        "ldp x3, x4, [sp], #16\n"
        "ldp x5, x6, [sp], #16\n"
        "ldp x7, x8, [sp], #16\n"
        "ldp x9, x10, [sp], #16\n"
        "ldp x11, x12, [sp], #16\n"
        "ldp x13, x14, [sp], #16\n"
        "ldp x15, x16, [sp], #16\n"
        "ldp x17, x18, [sp], #16\n"
        "ldp x19, x20, [sp], #16\n"
        "ldp x21, x22, [sp], #16\n"
        "ldp x23, x24, [sp], #16\n"
        "ldp x25, x26, [sp], #16\n"
        "ldp x27, x28, [sp], #16\n"
        "ldp fp, lr, [sp], #16\n"

        /* restore {q0-q7} */
        "ldp q0, q1, [sp], #32\n"
        "ldp q2, q3, [sp], #32\n"
        "ldp q4, q5, [sp], #32\n"
        "ldp q6, q7, [sp], #32\n");
}

// just like pre_call, wow!
void function_context_begin_invocation(ZzHookFunctionEntry *entry, RegState *rs,
                                       zpointer caller_ret_addr, zpointer next_hop) {

    Xdebug("target %p call begin-invocation", entry->target_ptr);
    ZzThreadStack *stack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if (!stack) {
        stack = ZzNewThreadStack(entry->thread_local_key);
    }

    ZzCallStack *callstack = ZzNewCallStack();
    ZzPushCallStack(stack, callstack);

    if (entry->pre_call) {
        PRECALL pre_call;
        pre_call = entry->pre_call;
        (*pre_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }

    if (entry->replace_call) {
        *(zpointer *)next_hop = entry->replace_call;
    } else {
        *(zpointer *)next_hop = entry->on_invoke_trampoline;
    }

    if (entry->hook_type == HOOK_FUNCTION_TYPE) {
        callstack->caller_ret_addr = *(zpointer *)caller_ret_addr;
        *(zpointer *)caller_ret_addr = entry->on_leave_trampoline;
    }
}

// just like post_call, wow!
void function_context_half_invocation(ZzHookFunctionEntry *entry, RegState *rs,
                                      zpointer caller_ret_addr, zpointer next_hop) {
    Xdebug("target %p call half-invocation", entry->target_ptr);
    ZzThreadStack *stack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if (!stack) {
#if defined(DEBUG_MODE)
        debug_break();
#endif
    }
    ZzCallStack *callstack = ZzPopCallStack(stack);

    if (entry->half_call) {
        HALFCALL half_call;
        half_call = entry->half_call;
        (*half_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }
    *(zpointer *)next_hop = (zpointer)entry->target_half_ret_addr;

    ZzFreeCallStack(callstack);
}

// just like post_call, wow!
void function_context_end_invocation(ZzHookFunctionEntry *entry, RegState *rs, zpointer next_hop) {
    Xdebug("%p call end-invocation", entry->target_ptr);
    ZzThreadStack *stack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if (!stack) {
#if defined(DEBUG_MODE)
        debug_break();
#endif
    }
    ZzCallStack *callstack = ZzPopCallStack(stack);

    if (entry->post_call) {
        POSTCALL post_call;
        post_call = entry->post_call;
        (*post_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }
    *(zpointer *)next_hop = callstack->caller_ret_addr;

    ZzFreeCallStack(callstack);
}

void zz_arm64_thunker_build_enter_thunk(ZzWriter *writer) {
    /* save general registers and sp */
    zz_arm64_writer_put_bytes(writer, (void *)ctx_save, 26 * 4);
    zz_arm64_writer_put_sub_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 1 * 8);
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_X1, ARM64_REG_SP,
                                        8 + CTX_SAVE_STACK_OFFSET + 2 * 8);
    zz_arm64_writer_put_str_reg_reg_offset(writer, ARM64_REG_X1, ARM64_REG_SP, 0 * 8);

    /* alignment padding + dummy PC */
    zz_arm64_writer_put_sub_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 8);

    /* pass enter func args */
    /* entry */
    zz_arm64_writer_put_ldr_reg_reg_offset(writer, ARM64_REG_X0, ARM64_REG_SP,
                                           2 * 8 + 8 + CTX_SAVE_STACK_OFFSET);
    /* next hop*/
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_X1, ARM64_REG_SP,
                                        2 * 8 + 8 + CTX_SAVE_STACK_OFFSET + 0x8);

    /* RegState */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_X1, ARM64_REG_SP, 2 * 8);
    /* caller ret address */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_X1, ARM64_REG_SP, 2 * 8 + 8 + 28 * 8 + 8);

    /* call function_context_begin_invocation */
    zz_arm64_writer_put_ldr_blr_reg_address(writer, ARM64_REG_X17,
                                            (zaddr)function_context_begin_invocation);
    /* alignment padding + dummy PC */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 8);

    /* restore sp */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 1 * 8);

    /* restore general registers stack */
    zz_arm64_writer_put_bytes(writer, (void *)ctx_restore, 23 * 4);

    /* load next hop to x17 */
    zz_arm64_writer_put_ldr_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 8);

    /* restore next hop and arg stack */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 8);

    /* jump to next hop */
    zz_arm64_writer_put_br_reg(writer, ARM64_REG_X17);
}

void zz_arm64_thunker_build_half_thunk(ZzWriter *writer) {}
void zz_arm64_thunker_build_leave_thunk(ZzWriter *writer) {

    /* save general registers and sp */
    zz_arm64_writer_put_bytes(writer, (void *)ctx_save, 26 * 4);
    zz_arm64_writer_put_sub_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 1 * 8);
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_X1, ARM64_REG_SP,
                                        8 + CTX_SAVE_STACK_OFFSET + 2 * 8);
    zz_arm64_writer_put_str_reg_reg_offset(writer, ARM64_REG_X1, ARM64_REG_SP, 0 * 8);

    /* alignment padding + dummy PC */
    zz_arm64_writer_put_sub_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 8);

    /* pass enter func args */
    /* entry */
    zz_arm64_writer_put_ldr_reg_reg_offset(writer, ARM64_REG_X0, ARM64_REG_SP,
                                           2 * 8 + 8 + CTX_SAVE_STACK_OFFSET);
    /* next hop*/
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_X1, ARM64_REG_SP,
                                        2 * 8 + 8 + CTX_SAVE_STACK_OFFSET + 0x8);

    /* RegState */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_X2, ARM64_REG_SP, 2 * 8);

    /* call function_context_end_invocation */
    zz_arm64_writer_put_ldr_blr_reg_address(writer, ARM64_REG_X17,
                                            (zaddr)function_context_end_invocation);
    /* alignment padding + dummy PC */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 8);

    /* restore sp */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 1 * 8);

    /* restore general registers stack */
    zz_arm64_writer_put_bytes(writer, (void *)ctx_restore, 23 * 4);

    /* load next hop to x17 */
    zz_arm64_writer_put_ldr_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 8);

    /* restore next hop and arg stack */
    zz_arm64_writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 2 * 8);

    /* jump to next hop */
    zz_arm64_writer_put_br_reg(writer, ARM64_REG_X17);
}

void ZzThunkerBuildThunk(ZzInterceptorBackend *self) {
    zbyte temp_code_slice_data[256] = {0};
    ZzArm64Writer *arm64_writer;
    ZzCodeSlice *code_slice;
    ZZSTATUS status;
    arm64_writer = &self->arm64_writer;

    zz_arm64_writer_reset(arm64_writer, temp_code_slice_data);
    do {
        zz_arm64_thunker_build_enter_thunk(arm64_writer);
        if (code_slice) {
            if (!ZzMemoryPatchCode((zaddr)code_slice->data, arm64_writer->base, arm64_writer->size))
                return;
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

    self->leave_thunk = code_slice->data;

    return;
}
