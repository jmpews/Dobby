#include <SaitamaKit/CommonKit/log/log_kit.h>
#include <stdlib.h>
#include <string.h>

#include "debuglog.h"
#include "interceptor.h"
#include "trampoline.h"

// RetStatus ZzBuildHookGOT(zz_ptr_t target_ptr, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
//                          POSTCALL post_call_ptr) {
// #if defined(__i386__) || defined(__x86_64__)
//     DEBUGLOG_COMMON_LOG("%s", "x86 & x86_64 arch not support");
//     return RS_FAILED;
// #endif

//     RetStatus status                      = RS_DONE_HOOK;
//     ZzInterceptor *interceptor            = NULL;
//     HookEntrySet *hook_function_entry_set = NULL;
//     HookEntry *entry                      = NULL;
//     HookType hook_type;

//     interceptor = InterceptorSharedInstance();
//     if (!interceptor) {
//         return RS_FAILED;
//     }
//     hook_function_entry_set = &(interceptor->hook_function_entry_set);

//     do {
//         // check is already hooked ?
//         if (InterceptorFindHookEntry(target_ptr)) {
//             status = RS_ALREADY_HOOK;
//             break;
//         }
//         entry = (HookEntry *)malloc0(sizeof(HookEntry));

//         // TODO: check return status
//         HookEntryInitialize(entry, HOOK_TYPE_FUNCTION_via_GOT, target_ptr, replace_call_ptr, pre_call_ptr,
//                             post_call_ptr, false);
//         TrampolineBuildAll(interceptor->backend, entry);
//         InterceptorAddHookEntry(entry);

//         if (origin_ptr)
//             *origin_ptr = entry->on_invoke_trampoline;
//     } while (0);
//     return status;
// }

RetStatus ZzBuildHook(zz_ptr_t target_ptr, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                      POSTCALL post_call_ptr, bool try_near_jump, HookType hook_type) {
// HookZz do not support x86 now.
#if defined(__i386__) || defined(__x86_64__)
    DEBUGLOG_COMMON_LOG("%s", "x86 & x86_64 arch not support");
    return RS_FAILED;
#endif

    RetStatus status                      = RS_DONE_HOOK;
    ZzInterceptor *interceptor            = NULL;
    HookEntrySet *hook_function_entry_set = NULL;
    HookEntry *entry                      = NULL;

    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return RS_FAILED;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    do {
        // check is already hooked ?
        if (InterceptorFindHookEntry(target_ptr)) {
            status = RS_ALREADY_HOOK;
            break;
        }
        entry = (HookEntry *)malloc0(sizeof(HookEntry));

        // TODO: check return status
        HookEntryInitialize(entry, hook_type, target_ptr, replace_call_ptr, pre_call_ptr, post_call_ptr, try_near_jump);
        TrampolineBuildAll(interceptor->backend, entry);
        InterceptorAddHookEntry(entry);

        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;
    } while (0);
    return status;
}

void ZzEnableHook(zz_ptr_t target_ptr) {
    RetStatus status           = RS_DONE_ENABLE;
    ZzInterceptor *interceptor = NULL;
    HookEntry *entry           = NULL;

    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return;
    }
    entry = InterceptorFindHookEntry(target_ptr);

    if (!entry) {
        status = RS_NO_BUILD_HOOK;
        ERROR_LOG(" %p not build HookEntry!", target_ptr);
        return;
    }

    if (entry->isEnabled) {
        status = RS_ALREADY_ENABLED;
        ERROR_LOG("%p already enable!", target_ptr);
        return;
    } else {
        entry->isEnabled = true;
    }

    // key function.
    TrampolineActivate(interceptor->backend, entry);
    return;
}

RetStatus ZzDisableHook(zz_ptr_t target_ptr) {
    RetStatus status           = RS_DONE_ENABLE;
    ZzInterceptor *interceptor = NULL;
    HookEntry *entry           = NULL;

    entry       = InterceptorFindHookEntry(target_ptr);
    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return RS_FAILED;
    }

    MemoryHelperPatchCode((const zz_addr_t)entry->origin_prologue.address, entry->origin_prologue.data,
                          entry->origin_prologue.size);

    entry->isEnabled = false;

    return status;
}

RetStatus ZzHook(zz_ptr_t target_ptr, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                 POSTCALL post_call_ptr, bool try_near_jump) {
    HookType hook_type;
    if (pre_call_ptr || post_call_ptr) {
        hook_type = HOOK_TYPE_FUNCTION_via_PRE_POST;
    } else {
        hook_type = HOOK_TYPE_FUNCTION_via_REPLACE;
    }

    ZzBuildHook(target_ptr, replace_ptr, origin_ptr, pre_call_ptr, post_call_ptr, try_near_jump, hook_type);
    ZzEnableHook(target_ptr);
    return RS_SUCCESS;
}

RetStatus ZzHookPrePost(zz_ptr_t target_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr) {
    RetStatus status = RS_SUCCESS;
    status = ZzBuildHook(target_ptr, NULL, NULL, pre_call_ptr, post_call_ptr, FALSE, HOOK_TYPE_FUNCTION_via_PRE_POST);
    ZzEnableHook(target_ptr);
    return status;
}

RetStatus ZzHookReplace(zz_ptr_t target_ptr, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr) {
    RetStatus status = RS_SUCCESS;
    status = ZzBuildHook(target_ptr, replace_ptr, origin_ptr, NULL, NULL, FALSE, HOOK_TYPE_FUNCTION_via_REPLACE);
    ZzEnableHook(target_ptr);
    return status;
}

RetStatus ZzDynamicBinaryInstrumentation(zz_ptr_t insn_address, STUBCALL stub_call_ptr) {
    RetStatus status = RS_SUCCESS;
    ZzInterceptor *interceptor;
    HookEntry *entry;
    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return RS_FAILED;
    }

    // check is already hooked ?
    if (InterceptorFindHookEntry(insn_address)) {
        status = RS_ALREADY_HOOK;
        return status;
    }
    entry = (HookEntry *)malloc0(sizeof(HookEntry));

    HookEntryInitialize(entry, HOOK_TYPE_DBI, insn_address, NULL, NULL, NULL, true);
    entry->stub_call = stub_call_ptr;
    TrampolineBuildAll(interceptor->backend, entry);
    InterceptorAddHookEntry(entry);
    ZzEnableHook(insn_address);
    return status;
}