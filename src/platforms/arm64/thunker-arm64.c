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
#include "writer-arm64.h"

#include "interceptor.h"
#include "stack.h"
#include "thunker.h"

#include "zzdeps/common/debugbreak.h"

/*
    Programmer’s Guide for ARMv8-A:
        Page: (6-15)
        Page: (6-16)

    STP X9, X8, [X4]
        Stores the doubleword in X9 to address X4 and stores the doubleword in X8 to address X4 + 8.
    LDP X8, X2, [X0, #0x10]!
        Loads doubleword at address X0 + 0x10 into X8 and the doubleword at address X0 + 0x10 + 8 into X2 and add 0x10 to X0. See Figure 6-7.
 */
__attribute__((__naked__)) static void ctx_save()
{
    __asm__ volatile(

        /* reserve space for next_hop */
        "sub sp, sp, #(2*8)\n"

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

        /* save sp, x0 */
        "sub sp, sp, #(2*8)\n"
        "add x1, sp, #(2*8 + 8*16 + 30*8 + 2*8)\n"
        "stp x1, x0, [sp, #(0*8)]\n"

        /* alignment padding + dummy PC */
        "sub sp, sp, #(2*8)\n");
}

__attribute__((__naked__)) static void pass_enter_func_args()
{
    /* transfer args */
    __asm__ volatile("mov x0, x17\n"
                     "add x1, sp, #8\n"
                     "add x2, sp, #(2*8 + 2*8 + 28*8 + 8)\n"
                     "add x3, sp, #(2*8 + 2*8 + 30*8 + 8*16)\n");
}

__attribute__((__naked__)) static void pass_half_func_args()
{
    /* transfer args */
    __asm__ volatile("mov x0, x17\n"
                     "add x1, sp, #8\n"
                     "add x2, sp, #(2*8 + 2*8 + 28*8 + 8)\n"
                     "add x3, sp, #(2*8 + 2*8 + 30*8 + 8*16)\n");
}

__attribute__((__naked__)) static void pass_leave_func_args()
{
    /* transfer args */
    __asm__ volatile("mov x0, x17\n"
                     "add x1, sp, #8\n"
                     "add x2, sp, #(2*8 + 2*8 + 30*8 + 8*16)\n");
}

__attribute__((__naked__)) static void ctx_restore()
{
    __asm__ volatile(
        /* alignment padding + dummy PC */
        "add sp, sp, #(2*8)\n"

        /* restore sp, x0 */
        "ldp x1, x0, [sp], #16\n"

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
        "ldp q6, q7, [sp], #32\n"

        // //  next hop
        // //  ATTENTION: svc #x80, use x16 to transfer syscall number.
        // //  use x17 replace x16.
        // "ldp x16, x17, [sp], #16\n"
        // "br x16\n");

        /* next hop */
        "ldr x17, [sp], #16\n"
        "br x17\n");
}

// just like pre_call, wow!
void function_context_begin_invocation(ZzHookFunctionEntry *entry,
                                       RegState *rs,
                                       zpointer caller_ret_addr,
                                       zpointer next_hop)
{

    Xdebug("target %p call begin-invocation", entry->target_ptr);
    ZzThreadStack *stack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if(!stack) {
        stack = ZzNewThreadStack(entry->thread_local_key);
    }

    ZzCallStack *callstack = ZzNewCallStack();
    ZzPushCallStack(stack, callstack);
    
    if (entry->pre_call)
    {
        PRECALL pre_call;
        pre_call = entry->pre_call;
        (*pre_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }

    if (entry->replace_call)
    {
        *(zpointer *)next_hop = entry->replace_call;
    }
    else
    {
        *(zpointer *)next_hop = entry->on_invoke_trampoline;
    }

    if(entry->hook_type == HOOK_FUNCTION_TYPE)
    {
        callstack->caller_ret_addr = *(zpointer *)caller_ret_addr;
        *(zpointer *)caller_ret_addr = entry->on_leave_trampoline;

    }
}

// just like post_call, wow!
void function_context_half_invocation(ZzHookFunctionEntry *entry,
                                      RegState *rs,
                                      zpointer caller_ret_addr,
                                      zpointer next_hop)
{
    Xdebug("target %p call half-invocation", entry->target_ptr );
    ZzThreadStack *stack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if(!stack) {
        debug_break();
    }
    ZzCallStack *callstack =  ZzPopCallStack(stack);

    if (entry->half_call)
    {
        HALFCALL half_call;
        half_call = entry->half_call;
        (*half_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }
    *(zpointer *)next_hop = (zpointer)entry->target_half_ret_addr;
}

// just like post_call, wow!
void function_context_end_invocation(ZzHookFunctionEntry *entry,
                                     RegState *rs, zpointer next_hop)
{
    Xdebug("%p call end-invocation", entry->target_ptr);
    ZzThreadStack *stack = ZzGetCurrentThreadStack(entry->thread_local_key);
    if(!stack) {
        debug_break();
    }
    ZzCallStack *callstack =  ZzPopCallStack(stack);

    if (entry->post_call)
    {
        POSTCALL post_call;
        post_call = entry->post_call;
        (*post_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }
    *(zpointer *)next_hop = callstack->caller_ret_addr;
}

void ZzThunkerBuildEnterThunk(ZzWriter *writer)
{

    // pop x17
    writer_put_ldr_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 0);
    writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 16);

    // TODO:  is bad code ?
    writer_put_bytes(writer, (void *)ctx_save, 26 * 4);

    // call `function_context_begin_invocation`
    writer_put_bytes(writer, (void *)pass_enter_func_args, 4 * 4);
    writer_put_ldr_reg_address(
        writer, ARM64_REG_X17,
        (zaddr)(zpointer)function_context_begin_invocation);
    writer_put_blr_reg(writer, ARM64_REG_X17);

    // TOOD: is bad code ?
    writer_put_bytes(writer, (void *)ctx_restore, 23 * 4);
}

void ZzThunkerBuildHalfThunk(ZzWriter *writer)
{
    // pop x17
    writer_put_ldr_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 0);
    writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 16);

    // TODO:  is bad code ?
    writer_put_bytes(writer, (void *)ctx_save, 26 * 4);

    // call `function_context_half_invocation`
    writer_put_bytes(writer, (void *)pass_half_func_args, 4 * 4);
    writer_put_ldr_reg_address(
        writer, ARM64_REG_X17,
        (zaddr)(zpointer)function_context_half_invocation);
    writer_put_blr_reg(writer, ARM64_REG_X17);

    // TOOD: is bad code ?
    writer_put_bytes(writer, (void *)ctx_restore, 23 * 4);
}

void ZzThunkerBuildLeaveThunk(ZzWriter *writer)
{

    // pop x17
    writer_put_ldr_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 0);
    writer_put_add_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 16);

    // TODO:  is bad code ?
    writer_put_bytes(writer, (void *)ctx_save, 26 * 4);

    // call `function_context_end_invocation`
    writer_put_bytes(writer, (void *)pass_leave_func_args, 3 * 4);
    writer_put_ldr_reg_address(writer, ARM64_REG_X17,
                               (zaddr)(zpointer)function_context_end_invocation);
    writer_put_blr_reg(writer, ARM64_REG_X17);

    // TOOD: is bad code ?
    writer_put_bytes(writer, (void *)ctx_restore, 23 * 4);
}

/*
    作为跳板, 按理说需要两个寄存器, 一个寄存器用于跳转, 一个寄存器由于保存参数, 但是特么一下污染了两个寄存器.
    所以有个技巧: 利用栈实现只有一个寄存器就可以完成工作
 */
void ZzThunkerBuildJumpToEnterThunk(ZzWriter *writer, zpointer hookentry_ptr,
                                   zpointer enter_thunk_ptr)
{
    writer_put_ldr_reg_address(writer, ARM64_REG_X17, (zaddr)hookentry_ptr);

    // push x17
    writer_put_sub_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 16);
    writer_put_str_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 0);

    // jump to `dest`
    writer_put_ldr_reg_address(writer, ARM64_REG_X17, (zaddr)enter_thunk_ptr);
    writer_put_br_reg(writer, ARM64_REG_X17);
}

void ZzThunkerBuildJumpToHalfThunk(ZzWriter *writer, zpointer hookentry_ptr,
                                  zpointer half_thunk_ptr)
{
    writer_put_ldr_reg_address(writer, ARM64_REG_X17, (zaddr)hookentry_ptr);

    // push x17
    writer_put_sub_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 16);
    writer_put_str_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 0);

    // jump to `dest`
    writer_put_ldr_reg_address(writer, ARM64_REG_X17, (zaddr)half_thunk_ptr);
    writer_put_br_reg(writer, ARM64_REG_X17);
}

void ZzThunkerBuildJumpToLeaveThunk(ZzWriter *writer, zpointer hookentry_ptr,
                                   zpointer leave_thunk_ptr)
{
    writer_put_ldr_reg_address(writer, ARM64_REG_X17, (zaddr)hookentry_ptr);

    // push x17
    writer_put_sub_reg_reg_imm(writer, ARM64_REG_SP, ARM64_REG_SP, 16);
    writer_put_str_reg_reg_offset(writer, ARM64_REG_X17, ARM64_REG_SP, 0);

    // jump to `dest`
    writer_put_ldr_reg_address(writer, ARM64_REG_X17, (zaddr)leave_thunk_ptr);
    writer_put_br_reg(writer, ARM64_REG_X17);
}