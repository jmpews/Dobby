#include <stdlib.h>
#include <string.h>
#include <SaitamaKit/CommonKit/log/log_kit.h>

#include "interceptor.h"
#include "trampoline.h"
#include "debuglog.h"

#define ZZHOOKENTRIES_DEFAULT 100
ZzInterceptor *g_interceptor = NULL;

RetStatus InterceptorInitialize(void) {
    ZzInterceptor *interceptor = g_interceptor;
    HookEntrySet *hook_function_entry_set;

    if (NULL == interceptor) {
        interceptor = (ZzInterceptor *)malloc0(sizeof(ZzInterceptor));

        hook_function_entry_set           = &(interceptor->hook_function_entry_set);
        hook_function_entry_set->capacity = ZZHOOKENTRIES_DEFAULT;
        hook_function_entry_set->entries  = (HookEntry **)malloc0(
            sizeof(HookEntry *) * hook_function_entry_set->capacity);

        if (!hook_function_entry_set->entries) {
            return RS_FAILED;
        }
        hook_function_entry_set->size = 0;

        /* update g_intercepter */
        g_interceptor = interceptor;

        /* check rwx memory attributes */
        interceptor->is_support_rx_page = MemoryHelperIsSupportAllocateRXMemory();
        if (interceptor->is_support_rx_page) {
            interceptor->emm = ExecuteMemoryManagerSharedInstance();
            interceptor->backend   = InteceptorBackendNew(interceptor->emm);
        }

        return RS_DONE_INIT;
    }
    return RS_ALREADY_INIT;
}

static ZzInterceptor *InterceptorSharedInstance(void) {
    ZzInterceptor *interceptor = g_interceptor;

    /* check g_intercepter initialization */
    if (!interceptor) {
        InterceptorInitialize();
        if (!g_interceptor)
            return NULL;
        if (!g_interceptor->is_support_rx_page) {
            ERROR_LOG_STR("current device does not support allocating r-x memory page!");
            return NULL;
        }
    }

    interceptor = g_interceptor;
    return interceptor;
}

HookEntry *InterceptorFindHookEntry(zz_ptr_t target_ptr) {
    ZzInterceptor *interceptor                      = NULL;
    HookEntrySet *hook_function_entry_set = NULL;

    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return NULL;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    for (int i = 0; i < hook_function_entry_set->size; ++i) {
        if ((hook_function_entry_set->entries)[i] && target_ptr == (hook_function_entry_set->entries)[i]->target_ptr) {
            return (hook_function_entry_set->entries)[i];
        }
    }
    return NULL;
}

RetStatus InterceptorAddHookEntry(HookEntry *entry) {
    ZzInterceptor *interceptor                      = NULL;
    HookEntrySet *hook_function_entry_set = NULL;

    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return RS_FAILED;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    if (hook_function_entry_set->size >= hook_function_entry_set->capacity) {
        HookEntry **entries = (HookEntry **)realloc(
            hook_function_entry_set->entries, sizeof(HookEntry *) * hook_function_entry_set->capacity * 2);
        if (!entries)
            return RS_FAILED;

        hook_function_entry_set->capacity = hook_function_entry_set->capacity * 2;
        hook_function_entry_set->entries  = entries;
    }
    hook_function_entry_set->entries[hook_function_entry_set->size++] = entry;
    return RS_SUCCESS;
}

void HookEntryInitialize(HookEntry *entry, ZZHOOKTYPE hook_type, zz_ptr_t target_ptr,
                                   zz_ptr_t replace_call, PRECALL pre_call, POSTCALL post_call, bool try_near_jump) {
    ZzInterceptor *interceptor                      = NULL;
    HookEntrySet *hook_function_entry_set = NULL;

    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    entry->hook_type               = hook_type;
    entry->id                      = hook_function_entry_set->size;
    entry->isEnabled               = 0;
    entry->try_near_jump           = try_near_jump;
    entry->interceptor             = interceptor;
    entry->target_ptr              = target_ptr;
    entry->replace_call            = replace_call;
    entry->pre_call                = (zz_ptr_t)pre_call;
    entry->post_call               = (zz_ptr_t)post_call;
    entry->on_enter_trampoline     = NULL;
    entry->on_invoke_trampoline    = NULL;
    entry->on_leave_trampoline     = NULL;
    entry->origin_prologue.address = target_ptr;
    entry->thread_local_key        = ThreadNewThreadLocalKeyPtr();
}

void ZzFreeHookEntry(HookEntry *entry) {
    ZzInterceptor *interceptor                      = NULL;
    HookEntrySet *hook_function_entry_set = NULL;
    HookEntry **entries                   = NULL;

    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);
    entries                 = hook_function_entry_set->entries;

    int i;
    for (i = 0; i < hook_function_entry_set->size; ++i) {
        if (entries[i] && entry == entries[i]) {
            // exchange with the last item
            entries[i] = entries[hook_function_entry_set->size - 1];
        }
    }
    hook_function_entry_set->size--;

    // free thread local key
    ThreadFreeThreadLocalKeyPtr(entry->thread_local_key);
    TrampolineFree(entry);
}

RetStatus ZzBuildHook(zz_ptr_t target_ptr, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                     POSTCALL post_call_ptr, bool try_near_jump, ZZHOOKTYPE hook_type) {
// HookZz do not support x86 now.
#if defined(__i386__) || defined(__x86_64__)
    DEBUGLOG_COMMON_LOG("%s", "x86 & x86_64 arch not support");
    return RS_FAILED;
#endif

    RetStatus status                                 = RS_DONE_HOOK;
    ZzInterceptor *interceptor                      = NULL;
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
        HookEntryInitialize(entry, hook_type, target_ptr, replace_call_ptr, pre_call_ptr, post_call_ptr,
                                      try_near_jump);
        TrampolineBuildAll(interceptor->backend, entry);
        InterceptorAddHookEntry(entry);

        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;
    } while (0);
    return status;
}

RetStatus ZzBuildHookGOT(zz_ptr_t target_ptr, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                        POSTCALL post_call_ptr) {
#if defined(__i386__) || defined(__x86_64__)
    DEBUGLOG_COMMON_LOG("%s", "x86 & x86_64 arch not support");
    return RS_FAILED;
#endif

    RetStatus status                                 = RS_DONE_HOOK;
    ZzInterceptor *interceptor                      = NULL;
    HookEntrySet *hook_function_entry_set = NULL;
    HookEntry *entry                      = NULL;
    ZZHOOKTYPE hook_type;

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
        HookEntryInitialize(entry, HOOK_TYPE_FUNCTION_via_GOT, target_ptr, replace_call_ptr, pre_call_ptr,
                                      post_call_ptr, false);
        TrampolineBuildAll(interceptor->backend, entry);
        InterceptorAddHookEntry(entry);

        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;
    } while (0);
    return status;
}

void ZzEnableHook(zz_ptr_t target_ptr) {
    RetStatus status            = RS_DONE_ENABLE;
    ZzInterceptor *interceptor = NULL;
    HookEntry *entry = NULL;

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
    RetStatus status            = RS_DONE_ENABLE;
    ZzInterceptor *interceptor = NULL;
    HookEntry *entry = NULL;

    entry       = InterceptorFindHookEntry(target_ptr);
    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return RS_FAILED;
    }

    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
        ZzDisableHookGOT((const char *)target_ptr);
    } else {
        MemoryHelperPatchCode((const zz_addr_t)entry->origin_prologue.address, entry->origin_prologue.data,
                          entry->origin_prologue.size);
    }

    entry->isEnabled = false;

    return status;
}

RetStatus ZzHook(zz_ptr_t target_ptr, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                POSTCALL post_call_ptr, bool try_near_jump) {
    ZZHOOKTYPE hook_type;
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


// #ifdef TARGET_IS_IOS
// RetStatus StaticBinaryInstrumentation(zz_ptr_t target_fileoff, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr,
//                                      PRECALL pre_call_ptr, POSTCALL post_call_ptr) {
//     RetStatus status                                 = RS_DONE_HOOK;
//     ZzInterceptor *interceptor                      = g_interceptor;
//     HookEntrySet *hook_function_entry_set = NULL;
//     HookEntry *entry                      = NULL;

//     if (!interceptor) {
//         InterceptorInitialize();
//         if (!g_interceptor)
//             return RS_FAILED;
//     }

//     interceptor         = g_interceptor;
//     entry               = (HookEntry *)malloc0(sizeof(HookEntry));
//     entry->target_ptr   = target_fileoff;
//     entry->replace_call = replace_call_ptr;
//     entry->pre_call     = (zz_ptr_t)pre_call_ptr;
//     entry->post_call    = (zz_ptr_t)post_call_ptr;
//     ZzActivateSolidifyTrampoline(entry, (zz_addr_t)target_fileoff);
//     if (origin_ptr)
//         *origin_ptr = entry->on_invoke_trampoline;
//     return status;
// }
// #endif
