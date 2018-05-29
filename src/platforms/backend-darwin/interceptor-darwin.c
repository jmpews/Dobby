#include <stdlib.h>
#include <string.h>

#include "interceptor-darwin.h"
#include "interceptor.h"
#include "trampoline.h"
#include <debuglog.h>

#include <dlfcn.h>
#include <mach-o/dyld.h>

RetStatus ZzHookGOT(void *header, const char *name, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                    POSTCALL post_call_ptr) {
    intptr_t (*pub_dyld_get_image_slide)(const struct mach_header *mh);
    pub_dyld_get_image_slide = dlsym((void *)dlopen(0, RTLD_LAZY), "_dyld_get_image_slide");
    zz_ptr_t target_ptr;
    zz_size_t slide;
    const struct mach_header *macho_header = header;

    target_ptr = dlsym((void *)dlopen(0, RTLD_LAZY), name);

    if (!header) {
        macho_header = _dyld_get_image_header(0);
    }

    slide = pub_dyld_get_image_slide(macho_header);
    // normal fishhook
    if (replace_ptr) {
        ZzBuildHook((zz_ptr_t)name, target_ptr, origin_ptr, pre_call_ptr, post_call_ptr, false,
                    HOOK_TYPE_FUNCTION_via_GOT);
        HookEntry *entry = InterceptorFindHookEntry((zz_ptr_t)name);
        rebind_symbols_image((void *)header, slide, (struct rebinding[1]){{name, replace_ptr, (void **)origin_ptr}}, 1);
    } else if (strcmp(name, "objc_msgSend")) {
        ZzBuildHook((zz_ptr_t)name, target_ptr, origin_ptr, pre_call_ptr, post_call_ptr, false,
                    HOOK_TYPE_FUNCTION_via_GOT);
    } else {
        ZzBuildHook((zz_ptr_t)name, target_ptr, origin_ptr, pre_call_ptr, post_call_ptr, false,
                    HOOK_TYPE_FUNCTION_via_GOT);
        HookEntry *entry = InterceptorFindHookEntry((zz_ptr_t)name);
        rebind_symbols_image((void *)header, slide,
                             (struct rebinding[1]){{name, entry->on_enter_trampoline, (void **)origin_ptr}}, 1);
        if (DebugLogControlerIsEnableLog()) {
            DEBUGLOG_COMMON_LOG("ZzHookGOT: \n\ton_enter_trampoline: %p\n\ton_leave_trampoline: %p",
                                entry->on_enter_trampoline, entry->on_leave_trampoline);
        }
    }
    return RS_SUCCESS;
}

RetStatus ZzDisableHookGOT(const char *name) {
    intptr_t (*pub_dyld_get_image_slide)(const struct mach_header *mh);
    pub_dyld_get_image_slide         = dlsym((void *)dlopen(0, RTLD_LAZY), "_dyld_get_image_slide");
    zz_ptr_t target_ptr              = dlsym((void *)dlopen(0, RTLD_LAZY), name);
    const struct mach_header *header = _dyld_get_image_header(0);
    zz_size_t slide                  = pub_dyld_get_image_slide(header);
    HookEntry *entry                 = InterceptorFindHookEntry((zz_ptr_t)name);

    rebind_symbols_image((void *)header, slide, (struct rebinding[1]){{name, target_ptr, NULL}}, 1);
    return RS_SUCCESS;
}

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
//     ZzActivateStaticBinaryInstrumentationTrampoline(entry, (zz_addr_t)target_fileoff);
//     if (origin_ptr)
//         *origin_ptr = entry->on_invoke_trampoline;
//     return status;
// }
