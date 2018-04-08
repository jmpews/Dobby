//
// Created by z on 2018/4/7.
//

#include <CommonKit/log/log_kit.h>
#include <hookzz.h>
#include <debuglog.h>
#include "custom-bridge-handler.h"
#include "closure-bridge-arm64.h"

void context_begin_invocation(RegState *rs, HookEntry *entry, void *nextHop,
                                       void *retAddr) {
    DEBUG_LOG("target %p call begin-invocation", entry->target_ptr);

    // For iOS Easy Debug Breakpoint
    // if (!strcmp((char *)(rs->general.regs.x1), "_beginBackgroundTaskWithName:expirationHandler:")) {
    // }

    ThreadStack *threadstack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
    if (!threadstack) {
        threadstack = ThreadStackAllocate(entry->thread_local_key);
    }
    CallStack *callstack = CallStackAllocate();
    ThreadStackPushCallStack(threadstack, callstack);

    // call pre_call
    if (entry->pre_call) {
        PRECALL pre_call;
        HookEntryInfo entryInfo;
        entryInfo.hook_id      = entry->id;
        entryInfo.hook_address = entry->target_ptr;
        pre_call                = entry->pre_call;
        (*pre_call)(rs, (ThreadStackPublic *)threadstack, (CallStackPublic *)callstack, &entryInfo);
    }

    // set next hop
    if (entry->replace_call) {
        *(zz_ptr_t *)nextHop = entry->replace_call;
    } else {
        *(zz_ptr_t *)nextHop = entry->on_invoke_trampoline;
    }

    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST || entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
        callstack->retAddr   = *(zz_ptr_t *)retAddr;
        *(zz_ptr_t *)retAddr = entry->on_leave_trampoline;
    }
}

void context_begin_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    HookEntry *entry = cbd->user_data;
    void *nextHop_ptr = (void *)&rs->general.regs.x17;
    void *regLR_ptr = (void *)&rs->lr;
    context_begin_invocation(rs, entry, nextHop_ptr, regLR_ptr);
    return;
}

void context_end_invocation(RegState *rs, HookEntry *entry, void *nextHop) {
    DEBUG_LOG("%p call end-invocation", entry->target_ptr);

    ThreadStack *threadstack = ThreadStackGetByThreadLocalKey(entry->thread_local_key);
    if (!threadstack) {
    }
    CallStack *callstack = ThreadStackPopCallStack(threadstack);

    // call post_call
    if (entry->post_call) {
        POSTCALL post_call;
        HookEntryInfo entryInfo;
        entryInfo.hook_id = entry->id;
        entryInfo.hook_address = entry->target_ptr;
        post_call = entry->post_call;
        (*post_call)(rs, (ThreadStackPublic *) threadstack, (CallStackPublic *) callstack,
                     (const HookEntryInfo *) &entryInfo);
    }

    // set next hop
    *(zz_ptr_t *) nextHop = callstack->retAddr;
    CallStackFree(callstack);
}

void context_end_invocation_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    HookEntry *entry = cbd->user_data;
    void *nextHop_ptr = (void *)&rs->general.regs.x17;
    context_end_invocation(rs, entry, nextHop_ptr);
    return;
}

void dynamic_binary_instrumentation_invocation(RegState *rs, HookEntry *entry, void *nextHop) {
    DEBUG_LOG("target %p call dynamic-binary-instrumentation-invocation", entry->target_ptr);

    /* call pre_call */
    if (entry->stub_call) {
        STUBCALL stub_call;
        HookEntryInfo entryInfo;
        entryInfo.hook_id      = entry->id;
        entryInfo.hook_address = entry->target_ptr;
        stub_call               = entry->stub_call;
        (*stub_call)(rs, (const HookEntryInfo *)&entryInfo);
    }

    *(zz_ptr_t *)nextHop = entry->on_invoke_trampoline;
}

void dynamic_binary_instrumentationn_bridge_handler(RegState *rs, ClosureBridgeData *cbd) {
    HookEntry *entry = cbd->user_data;
    void *nextHop_ptr = (void *)&rs->general.regs.x17;
    dynamic_binary_instrumentation_invocation(rs, entry, nextHop_ptr);
    return;
}