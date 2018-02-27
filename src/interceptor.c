#include <stdlib.h>
#include <string.h>

#include "interceptor.h"
#include "trampoline.h"

#define ZZHOOKENTRIES_DEFAULT 100
ZzInterceptor *g_interceptor = NULL;

ZZSTATUS ZzInitializeInterceptor(void) {
    ZzInterceptor *interceptor = g_interceptor;
    ZzHookFunctionEntrySet *hook_function_entry_set;

    if (NULL == interceptor) {
        interceptor = (ZzInterceptor *)zz_malloc_with_zero(sizeof(ZzInterceptor));

        hook_function_entry_set           = &(interceptor->hook_function_entry_set);
        hook_function_entry_set->capacity = ZZHOOKENTRIES_DEFAULT;
        hook_function_entry_set->entries  = (ZzHookFunctionEntry **)zz_malloc_with_zero(
            sizeof(ZzHookFunctionEntry *) * hook_function_entry_set->capacity);

        if (!hook_function_entry_set->entries) {
            return ZZ_FAILED;
        }
        hook_function_entry_set->size = 0;

        /* update g_intercepter */
        g_interceptor = interceptor;

        /* check rwx memory attributes */
        interceptor->is_support_rx_page = ZzMemoryIsSupportAllocateRXPage();
        if (interceptor->is_support_rx_page) {
            interceptor->allocator = ZzNewAllocator();
            interceptor->backend   = ZzBuildInteceptorBackend(interceptor->allocator);
        }

        return ZZ_DONE_INIT;
    }
    return ZZ_ALREADY_INIT;
}

static ZzInterceptor *ZzGlobalInterceptorInstance(void) {
    ZzInterceptor *interceptor = g_interceptor;

    /* check g_intercepter initialization */
    if (!interceptor) {
        ZzInitializeInterceptor();
        if (!g_interceptor)
            return NULL;
        if (!g_interceptor->is_support_rx_page) {
            ZZ_ERROR_LOG_STR("current device does not support allocating r-x memory page!");
            return NULL;
        }
    }

    interceptor = g_interceptor;
    return interceptor;
}

ZzHookFunctionEntry *ZzFindHookFunctionEntry(zz_ptr_t target_ptr) {
    ZzInterceptor *interceptor                      = NULL;
    ZzHookFunctionEntrySet *hook_function_entry_set = NULL;

    interceptor = ZzGlobalInterceptorInstance();
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

ZZSTATUS ZzAddHookFunctionEntry(ZzHookFunctionEntry *entry) {
    ZzInterceptor *interceptor                      = NULL;
    ZzHookFunctionEntrySet *hook_function_entry_set = NULL;

    interceptor = ZzGlobalInterceptorInstance();
    if (!interceptor) {
        return ZZ_FAILED;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    if (hook_function_entry_set->size >= hook_function_entry_set->capacity) {
        ZzHookFunctionEntry **entries = (ZzHookFunctionEntry **)realloc(
            hook_function_entry_set->entries, sizeof(ZzHookFunctionEntry *) * hook_function_entry_set->capacity * 2);
        if (!entries)
            return ZZ_FAILED;

        hook_function_entry_set->capacity = hook_function_entry_set->capacity * 2;
        hook_function_entry_set->entries  = entries;
    }
    hook_function_entry_set->entries[hook_function_entry_set->size++] = entry;
    return ZZ_SUCCESS;
}

void ZzInitializeHookFunctionEntry(ZzHookFunctionEntry *entry, ZZHOOKTYPE hook_type, zz_ptr_t target_ptr,
                                   zz_ptr_t replace_call, PRECALL pre_call, POSTCALL post_call, bool try_near_jump) {
    ZzInterceptor *interceptor                      = NULL;
    ZzHookFunctionEntrySet *hook_function_entry_set = NULL;

    interceptor = ZzGlobalInterceptorInstance();
    if (!interceptor) {
        return;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    entry->hook_type            = hook_type;
    entry->id                   = hook_function_entry_set->size;
    entry->isEnabled            = 0;
    entry->try_near_jump        = try_near_jump;
    entry->interceptor          = interceptor;
    entry->target_ptr           = target_ptr;
    entry->replace_call         = replace_call;
    entry->pre_call             = (zz_ptr_t)pre_call;
    entry->post_call            = (zz_ptr_t)post_call;
    entry->on_enter_trampoline  = NULL;
    entry->on_invoke_trampoline = NULL;
    //    entry->on_half_trampoline      = NULL;
    entry->on_leave_trampoline     = NULL;
    entry->origin_prologue.address = target_ptr;
    entry->thread_local_key        = ZzThreadNewThreadLocalKeyPtr();
}

void ZzFreeHookFunctionEntry(ZzHookFunctionEntry *entry) {
    ZzInterceptor *interceptor                      = NULL;
    ZzHookFunctionEntrySet *hook_function_entry_set = NULL;
    ZzHookFunctionEntry **entries                   = NULL;

    interceptor = ZzGlobalInterceptorInstance();
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
    ZzThreadFreeThreadLocalKeyPtr(entry->thread_local_key);
    ZzFreeTrampoline(entry);
}

ZZSTATUS ZzBuildHook(zz_ptr_t target_ptr, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                     POSTCALL post_call_ptr, bool try_near_jump, ZZHOOKTYPE hook_type) {
// HookZz do not support x86 now.
#if defined(__i386__) || defined(__x86_64__)
    HookZzDebugInfoLog("%s", "x86 & x86_64 arch not support");
    return ZZ_FAILED;
#endif

    ZZSTATUS status                                 = ZZ_DONE_HOOK;
    ZzInterceptor *interceptor                      = NULL;
    ZzHookFunctionEntrySet *hook_function_entry_set = NULL;
    ZzHookFunctionEntry *entry                      = NULL;

    interceptor = ZzGlobalInterceptorInstance();
    if (!interceptor) {
        return ZZ_FAILED;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    do {
        // check is already hooked ?
        if (ZzFindHookFunctionEntry(target_ptr)) {
            status = ZZ_ALREADY_HOOK;
            break;
        }
        entry = (ZzHookFunctionEntry *)zz_malloc_with_zero(sizeof(ZzHookFunctionEntry));

        // TODO: check return status
        ZzInitializeHookFunctionEntry(entry, hook_type, target_ptr, replace_call_ptr, pre_call_ptr, post_call_ptr,
                                      try_near_jump);
        ZzBuildTrampoline(interceptor->backend, entry);
        ZzAddHookFunctionEntry(entry);

        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;
    } while (0);
    return status;
}

ZZSTATUS ZzBuildHookGOT(zz_ptr_t target_ptr, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                        POSTCALL post_call_ptr) {
#if defined(__i386__) || defined(__x86_64__)
    HookZzDebugInfoLog("%s", "x86 & x86_64 arch not support");
    return ZZ_FAILED;
#endif

    ZZSTATUS status                                 = ZZ_DONE_HOOK;
    ZzInterceptor *interceptor                      = NULL;
    ZzHookFunctionEntrySet *hook_function_entry_set = NULL;
    ZzHookFunctionEntry *entry                      = NULL;
    ZZHOOKTYPE hook_type;

    interceptor = ZzGlobalInterceptorInstance();
    if (!interceptor) {
        return ZZ_FAILED;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    do {
        // check is already hooked ?
        if (ZzFindHookFunctionEntry(target_ptr)) {
            status = ZZ_ALREADY_HOOK;
            break;
        }
        entry = (ZzHookFunctionEntry *)zz_malloc_with_zero(sizeof(ZzHookFunctionEntry));

        // TODO: check return status
        ZzInitializeHookFunctionEntry(entry, HOOK_TYPE_FUNCTION_via_GOT, target_ptr, replace_call_ptr, pre_call_ptr,
                                      post_call_ptr, false);
        ZzBuildTrampoline(interceptor->backend, entry);
        ZzAddHookFunctionEntry(entry);

        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;
    } while (0);
    return status;
}

// TODO: delete
#if 0
ZZSTATUS ZzBuildHookOneInstruction(zz_ptr_t insn_address, zz_ptr_t target_end_ptr, PRECALL pre_call_ptr, POSTCALL  post_call_ptr, bool try_near_jump) {
    // HookZz do not support x86 now.
#if defined(__i386__) || defined(__x86_64__)
    HookZzDebugInfoLog("%s", "x86 & x86_64 arch not support");
    return ZZ_FAILED;
#endif

    ZZSTATUS status                                 = ZZ_DONE_HOOK;
    ZzInterceptor *interceptor                      = NULL;
    ZzHookFunctionEntrySet *hook_function_entry_set = NULL;
    ZzHookFunctionEntry *entry                      = NULL;

    interceptor             = ZzGlobalInterceptorInstance();
    if(!interceptor) {
        return ZZ_FAILED;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    do {
        // check is already hooked ?
        if (ZzFindHookFunctionEntry(insn_address)) {
            status = ZZ_ALREADY_HOOK;
            break;
        }

        // TODO: check return status
        entry = (ZzHookFunctionEntry *)zz_malloc_with_zero(sizeof(ZzHookFunctionEntry));
        ZzInitializeHookFunctionEntry(entry, HOOK_TYPE_ONE_INSTRUCTION, insn_address, NULL,
                                      pre_call_ptr, post_call_ptr, try_near_jump);
        status = ZzBuildTrampoline(interceptor->backend, entry);
        ZzAddHookFunctionEntry(entry);
    } while (0);
    return status;
}
#endif

ZZSTATUS ZzEnableHook(zz_ptr_t target_ptr) {
    ZZSTATUS status            = ZZ_DONE_ENABLE;
    ZzInterceptor *interceptor = NULL;
    ZzHookFunctionEntry *entry = NULL;

    interceptor = ZzGlobalInterceptorInstance();
    if (!interceptor) {
        return ZZ_FAILED;
    }
    entry = ZzFindHookFunctionEntry(target_ptr);

    if (!entry) {
        status = ZZ_NO_BUILD_HOOK;
        ZZ_ERROR_LOG(" %p not build HookFunctionEntry!", target_ptr);
        return status;
    }

    if (entry->isEnabled) {
        status = ZZ_ALREADY_ENABLED;
        ZZ_ERROR_LOG("%p already enable!", target_ptr);
        return status;
    } else {
        entry->isEnabled = true;
    }

    // key function.
    return ZzActivateTrampoline(interceptor->backend, entry);
}

ZZSTATUS ZzDisableHook(zz_ptr_t target_ptr) {
    ZZSTATUS status            = ZZ_DONE_ENABLE;
    ZzInterceptor *interceptor = NULL;
    ZzHookFunctionEntry *entry = NULL;

    entry       = ZzFindHookFunctionEntry(target_ptr);
    interceptor = ZzGlobalInterceptorInstance();
    if (!interceptor) {
        return ZZ_FAILED;
    }

    if (entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
        ZzDisableHookGOT((const char *)target_ptr);
    } else {
        ZzMemoryPatchCode((const zz_addr_t)entry->origin_prologue.address, entry->origin_prologue.data,
                          entry->origin_prologue.size);
    }

    entry->isEnabled = false;

    return status;
}

ZZSTATUS ZzHook(zz_ptr_t target_ptr, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                POSTCALL post_call_ptr, bool try_near_jump) {
    ZZHOOKTYPE hook_type;
    if (pre_call_ptr || post_call_ptr) {
        hook_type = HOOK_TYPE_FUNCTION_via_PRE_POST;
    } else {
        hook_type = HOOK_TYPE_FUNCTION_via_REPLACE;
    }

    ZzBuildHook(target_ptr, replace_ptr, origin_ptr, pre_call_ptr, post_call_ptr, try_near_jump, hook_type);
    ZzEnableHook(target_ptr);
    return ZZ_SUCCESS;
}

ZZSTATUS ZzHookPrePost(zz_ptr_t target_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr) {
    ZZSTATUS status = ZZ_SUCCESS;
    status = ZzBuildHook(target_ptr, NULL, NULL, pre_call_ptr, post_call_ptr, FALSE, HOOK_TYPE_FUNCTION_via_PRE_POST);
    status = ZzEnableHook(target_ptr);
    return status;
}

ZZSTATUS ZzHookReplace(zz_ptr_t target_ptr, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr) {
    ZZSTATUS status = ZZ_SUCCESS;
    status = ZzBuildHook(target_ptr, replace_ptr, origin_ptr, NULL, NULL, FALSE, HOOK_TYPE_FUNCTION_via_REPLACE);
    status = ZzEnableHook(target_ptr);
    return status;
}

ZZSTATUS ZzDynamicBinaryInstrumentation(zz_ptr_t insn_address, STUBCALL stub_call_ptr) {
    ZZSTATUS status = ZZ_SUCCESS;
    ZzInterceptor *interceptor;
    ZzHookFunctionEntry *entry;
    interceptor = ZzGlobalInterceptorInstance();
    if (!interceptor) {
        return ZZ_FAILED;
    }

    // check is already hooked ?
    if (ZzFindHookFunctionEntry(insn_address)) {
        status = ZZ_ALREADY_HOOK;
        return status;
    }
    entry = (ZzHookFunctionEntry *)zz_malloc_with_zero(sizeof(ZzHookFunctionEntry));
    ZzInitializeHookFunctionEntry(entry, HOOK_TYPE_DBI, insn_address, NULL, NULL, NULL, true);
    entry->stub_call = stub_call_ptr;
    ZzBuildTrampoline(interceptor->backend, entry);
    ZzAddHookFunctionEntry(entry);

    status = ZzEnableHook(insn_address);
    return status;
}

ZZSTATUS ZzHookOneInstruction(zz_ptr_t insn_address, PRECALL pre_call_ptr, POSTCALL post_call_ptr, bool try_near_jump) {
    ZZSTATUS status = ZZ_SUCCESS;
    status =
        ZzBuildHook(insn_address, NULL, NULL, pre_call_ptr, post_call_ptr, try_near_jump, HOOK_TYPE_ONE_INSTRUCTION);
    status = ZzEnableHook(insn_address);
    return status;
}

// #ifdef TARGET_IS_IOS
// ZZSTATUS StaticBinaryInstrumentation(zz_ptr_t target_fileoff, zz_ptr_t replace_call_ptr, zz_ptr_t *origin_ptr,
//                                      PRECALL pre_call_ptr, POSTCALL post_call_ptr) {
//     ZZSTATUS status                                 = ZZ_DONE_HOOK;
//     ZzInterceptor *interceptor                      = g_interceptor;
//     ZzHookFunctionEntrySet *hook_function_entry_set = NULL;
//     ZzHookFunctionEntry *entry                      = NULL;

//     if (!interceptor) {
//         ZzInitializeInterceptor();
//         if (!g_interceptor)
//             return ZZ_FAILED;
//     }

//     interceptor         = g_interceptor;
//     entry               = (ZzHookFunctionEntry *)zz_malloc_with_zero(sizeof(ZzHookFunctionEntry));
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
