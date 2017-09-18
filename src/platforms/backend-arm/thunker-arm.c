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

#include "thunker-arm.h"

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

__attribute__((__naked__)) static void ctx_save() {
    __asm__ volatile(
        /* reserve space for next_hop and for cpsr */
        // "sub sp, sp, #(2*4)\n"

        /* save {r0-r7} */
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
        "str r0, [sp, #(0*4)]\n"

        /* save sp */
        "sub sp, sp, #(2*4)\n"
        "add r1, sp, #(2*4+14*4)\n"
        "str r1, [sp, #(0*4)]\n");
}

__attribute__((__naked__)) static void pass_enter_func_args() {
    /* transfer args */
    __asm__ volatile("ldr r0, [sp, #(0)]\n"
                     "add r1, sp, #8\n"
                     "add r2, sp, #(2*4 + 13*4)\n"
                     "add r3, sp, #(2*4 + 14*4 + 4)\n");
}

// __attribute__((__naked__)) static void pass_leave_func_args() {
//     /* transfer args */
//     __asm__ volatile("ldr r0, [sp, #(0)]\n"
//                      "add r1, sp, #8\n"
//                      "add r2, sp, #(2*4 + 13*4)\n"
//                      "add r3, sp, #(2*4 + 14*4 + 4)\n");
// }

__attribute__((__naked__)) static void ctx_restore() {
    __asm__ volatile(
        /* restore sp(fake) */
        "add sp, sp, #(2*4)\n"

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

        "ldr lr, [sp], #4\n"

        "ldr pc, [sp], #8\n");
}

// just like pre_call, wow!
void function_context_begin_invocation(ZzHookFunctionEntry *entry, RegState *rs,
                                       zpointer caller_ret_addr,
                                       zpointer next_hop) {

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
                                      zpointer caller_ret_addr,
                                      zpointer next_hop) {
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
void function_context_end_invocation(ZzHookFunctionEntry *entry, RegState *rs,
                                     zpointer next_hop) {
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

void zz_thumb_thunker_build_enter_thunk(ZzWriter *writer) {

    /* reserve space for next_hop and for cpsr */
    zz_arm_writer_put_sub_reg_reg_imm(writer, ARM_REG_SP, ARM_REG_SP, 2 * 4);

    zz_arm_writer_put_bytes(writer, (void *)ctx_save, 26 * 4);

    zz_arm_writer_put_bytes(writer, (void *)pass_enter_func_args, 4 * 4);

    zz_arm_writer_put_bytes(writer, (void *)ctx_restore, 23 * 4);
    zz_arm_writer_put_ldr_reg_reg_imm(writer, ARM_REG_PC, ARM_REG_SP, 0);
}

void ZzThunkerBuildHalfThunk(ZzWriter *writer) {}

void ZzThunkerBuildLeaveThunk(ZzWriter *writer) {}

void ZzThunkerBuildThunk(ZzInterceptorBackend *self) {
    zbyte temp_code_slice_data[256];
    ZzThumbWriter *thumb_writer;
    ZzCodeSlice *code_slice;
    ZZSTATUS status;
    thumb_writer = &self->thumb_writer;

    zz_thumb_writer_reset(thumb_writer, temp_code_slice_data);
    zz_thumb_thunker_build_enter_thunk(thumb_writer);

    code_slice = ZzNewCodeSlice(self->allocator, thumb_writer->size);
    if (!ZzMemoryPatchCode((zaddr)code_slice->data, temp_code_slice_data,
                           thumb_writer->size))
        return;

    self->leave_thunk = code_slice->data;

    return;
}
