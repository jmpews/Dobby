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

#include "bridge-x86.h"
#include "zzinfo.h"
#include <string.h>

// just like pre_call, wow!
void function_context_begin_invocation(HookEntry *entry, zz_ptr_t nextHop, RegState *rs,
                                       zz_ptr_t retAddr) {
    DEBUG_LOG("target %p call begin-invocation", entry->target_ptr);

    ThreadStack *stack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
    if (!stack) {
        stack = ThreadStackAllocate(entry->thread_local_key);
    }
    CallStack *callstack = CallStackAllocate();
    ThreadStackPushCallStack(stack, callstack);

    /* call pre_call */
    if (entry->pre_call) {
        PRECALL pre_call;
        pre_call = entry->pre_call;
        (*pre_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }

    /* set next hop */
    if (entry->replace_call) {
        *(zz_ptr_t *)nextHop = entry->replace_call;
    } else {
        *(zz_ptr_t *)nextHop = entry->on_invoke_trampoline;
    }

    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
        callstack->retAddr   = *(zz_ptr_t *)retAddr;
        *(zz_ptr_t *)retAddr = entry->on_leave_trampoline;
    }
}

// just like post_call, wow!
void function_context_half_invocation(HookEntry *entry, zz_ptr_t nextHop, RegState *rs,
                                      zz_ptr_t retAddr) {
    DEBUG_LOG("target %p call half-invocation", entry->target_ptr);

    ThreadStack *stack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
    if (!stack) {
#if defined(DEBUG_MODE)
        debug_break();
#endif
    }
    CallStack *callstack = ThreadStackPopCallStack(stack);

    // call half_call
    if (entry->half_call) {
        HALFCALL half_call;
        half_call = entry->half_call;
        (*half_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }

    /*  set next hop */
    *(zz_ptr_t *)nextHop = (zz_ptr_t)entry->target_half_ret_addr;

    CallStackFree(callstack);
}

// just like post_call, wow!
void function_context_end_invocation(HookEntry *entry, zz_ptr_t nextHop, RegState *rs) {
    DEBUG_LOG("%p call end-invocation", entry->target_ptr);

    ThreadStack *stack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
    if (!stack) {
#if defined(DEBUG_MODE)
        debug_break();
#endif
    }
    CallStack *callstack = ThreadStackPopCallStack(stack);

    /* call post_call */
    if (entry->post_call) {
        POSTCALL post_call;
        post_call = entry->post_call;
        (*post_call)(rs, (ThreadStack *)stack, (CallStack *)callstack);
    }

    /* set next hop */
    *(zz_ptr_t *)nextHop = callstack->retAddr;
    CallStackFree(callstack);
}

void zz_x86_bridge_build_enter_bridge(ZzAssemblerWriter *writer) {}

void zz_x86_bridge_build_insn_leave_bridge(ZzAssemblerWriter *writer) {}

void zz_x86_bridge_build_leave_bridge(ZzAssemblerWriter *writer) {}

void BridgeBuildAll(InterceptorBackend *self) { return RS_FAILED; }
