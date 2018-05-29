#include <SaitamaKit/CommonKit/log/log_kit.h>
#include <stdlib.h>
#include <string.h>

#include "debuglog.h"
#include "interceptor.h"
#include "trampoline.h"

#define ZZHOOKENTRIES_DEFAULT 100
ZzInterceptor *g_interceptor = NULL;

RetStatus InterceptorInitialize(void) {
    ZzInterceptor *interceptor = g_interceptor;
    HookEntrySet *hook_function_entry_set;

    if (NULL == interceptor) {
        interceptor = (ZzInterceptor *)malloc0(sizeof(ZzInterceptor));

        hook_function_entry_set           = &(interceptor->hook_function_entry_set);
        hook_function_entry_set->capacity = ZZHOOKENTRIES_DEFAULT;
        hook_function_entry_set->entries =
            (HookEntry **)malloc0(sizeof(HookEntry *) * hook_function_entry_set->capacity);

        if (!hook_function_entry_set->entries) {
            return RS_FAILED;
        }
        hook_function_entry_set->size = 0;

        /* update g_intercepter */
        g_interceptor = interceptor;

        /* check rwx memory attributes */
        interceptor->is_support_rx_page = MemoryHelperIsSupportAllocateRXMemory();
        if (interceptor->is_support_rx_page) {
            interceptor->emm     = ExecuteMemoryManagerSharedInstance();
            interceptor->backend = InteceptorBackendNew(interceptor->emm);
        }

        return RS_DONE_INIT;
    }
    return RS_ALREADY_INIT;
}

ZzInterceptor *InterceptorSharedInstance(void) {
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
    ZzInterceptor *interceptor            = NULL;
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
    ZzInterceptor *interceptor            = NULL;
    HookEntrySet *hook_function_entry_set = NULL;

    interceptor = InterceptorSharedInstance();
    if (!interceptor) {
        return RS_FAILED;
    }
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    if (hook_function_entry_set->size >= hook_function_entry_set->capacity) {
        HookEntry **entries = (HookEntry **)realloc(hook_function_entry_set->entries,
                                                    sizeof(HookEntry *) * hook_function_entry_set->capacity * 2);
        if (!entries)
            return RS_FAILED;

        hook_function_entry_set->capacity = hook_function_entry_set->capacity * 2;
        hook_function_entry_set->entries  = entries;
    }
    hook_function_entry_set->entries[hook_function_entry_set->size++] = entry;
    return RS_SUCCESS;
}

void HookEntryInitialize(HookEntry *entry, HookType hook_type, zz_ptr_t target_ptr, zz_ptr_t replace_call,
                         PRECALL pre_call, POSTCALL post_call, bool try_near_jump) {
    ZzInterceptor *interceptor            = NULL;
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

void FreeHookEntry(HookEntry *entry) {
    ZzInterceptor *interceptor            = NULL;
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
