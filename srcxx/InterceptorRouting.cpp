#include "interceptor_routing.h"

void interceptor_routing_begin(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR, void *ret_addr_PTR) {
    // DEBUG_LOG("target %p call begin-invocation", entry->target_ptr);

    // call pre_call
    if (entry->pre_call) {
        PRECALL pre_call;
        HookEntryInfo entryInfo;
        entryInfo.hook_id        = entry->id;
        entryInfo.target_address = entry->target_address;
        pre_call                 = entry->pre_call;
        (*pre_call)(rs, (ThreadStackPublic *)NULL, (CallStackPublic *)NULL, &entryInfo);
    }

    // set next hop
    if (entry->replace_call) {
        *(zz_ptr_t *)next_hop_addr_PTR = entry->replace_call;
    } else {
        *(zz_ptr_t *)next_hop_addr_PTR = entry->on_invoke_trampoline;
    }

    if (entry->type == HOOK_TYPE_FUNCTION_via_PRE_POST || entry->type == HOOK_TYPE_FUNCTION_via_GOT) {
        // TODO
        // callStack->ret_addr_PTR   = *(zz_ptr_t *)ret_addr_PTR;
        *(zz_ptr_t *)ret_addr_PTR = entry->on_leave_trampoline;
    }
}

void interceptor_routing_end(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR) {
    // DEBUG_LOG("%p call end-invocation", entry->target_ptr);

    // call post_call
    if (entry->post_call) {
        POSTCALL post_call;
        HookEntryInfo entryInfo;
        entryInfo.hook_id        = entry->id;
        entryInfo.target_address = entry->target_address;
        post_call                = entry->post_call;
        (*post_call)(rs, (ThreadStackPublic *)NULL, (CallStackPublic *)NULL, (const HookEntryInfo *)&entryInfo);
    }

    // TODO
    // set next hop
    // *(zz_ptr_t *)next_hop_addr_PTR = callStack->ret_addr_PTR;
}

void interceptor_routing_dynamic_binary_instrumentation(RegState *rs, hook_entry_t *entry, void *next_hop_addr_PTR) {
    // DEBUG_LOG("target %p call dynamic-binary-instrumentation-invocation", entry->target_ptr);

    if (entry->stub_call) {
        STUBCALL stub_call;
        HookEntryInfo entryInfo;
        entryInfo.hook_id        = entry->id;
        entryInfo.target_address = entry->target_address;
        stub_call                = entry->stub_call;
        (*stub_call)(rs, (const HookEntryInfo *)&entryInfo);
    }

    *(zz_ptr_t *)next_hop_addr_PTR = entry->on_invoke_trampoline;
}

void interceptor_routing_begin_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {
    hook_entry_t *entry     = cbInfo->user_data;
    void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
    void *ret_addr_PTR      = get_ret_addr_PTR(rs);
    interceptor_routing_begin(rs, entry, next_hop_addr_PTR, ret_addr_PTR);
    return;
}

void interceptor_routing_end_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {
    hook_entry_t *entry     = cbInfo->user_data;
    void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
    interceptor_routing_end(rs, entry, next_hop_addr_PTR);
    return;
}

void interceptor_routing_dynamic_binary_instrumentation_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {
    hook_entry_t *entry     = cbInfo->user_data;
    void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
    interceptor_routing_dynamic_binary_instrumentation(rs, entry, next_hop_addr_PTR);
    return;
}

void interceptor_routing_common_bridge_handler(RegState *rs, ClosureBridgeInfo *cbInfo) {
    USER_CODE_CALL userCodeCall = cbInfo->user_code;
    userCodeCall(rs, cbInfo);
    return;
}

void interceptor_routing_begin_dynamic_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo) {
    hook_entry_t *entry     = dcbInfo->user_data;
    void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
    void *ret_addr_PTR      = get_ret_addr_PTR(rs);
    interceptor_routing_begin(rs, entry, next_hop_addr_PTR, ret_addr_PTR);
    return;
}

void interceptor_routing_end_dynamic_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo) {
    hook_entry_t *entry     = dcbInfo->user_data;
    void *next_hop_addr_PTR = get_next_hop_addr_PTR(rs);
    interceptor_routing_end(rs, entry, next_hop_addr_PTR);
    return;
}

void interceptor_routing_dynamic_common_bridge_handler(RegState *rs, DynamicClosureBridgeInfo *dcbInfo) {
    DYNAMIC_USER_CODE_CALL userCodeCall = dcbInfo->user_code;
    userCodeCall(rs, dcbInfo);
    return;
}