#include <stdlib.h>
#include <string.h>

#include "interceptor-darwin.h"
#include "interceptor.h"
#include "trampoline.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>

ZZSTATUS ZzHookGOT(const char *name, zz_ptr_t replace_ptr, zz_ptr_t *origin_ptr, PRECALL pre_call_ptr,
                   POSTCALL post_call_ptr) {
    intptr_t (*pub_dyld_get_image_slide)(const struct mach_header *mh);
    pub_dyld_get_image_slide         = dlsym((void *)dlopen(0, RTLD_LAZY), "_dyld_get_image_slide");
    zz_ptr_t target_ptr              = dlsym((void *)dlopen(0, RTLD_LAZY), name);
    const struct mach_header *header = _dyld_get_image_header(0);
    zz_size_t slide                  = pub_dyld_get_image_slide(header);

    if (replace_ptr) {
        ZzBuildHookGOT((zz_ptr_t)name, replace_ptr, origin_ptr, pre_call_ptr, post_call_ptr);
    } else {
        ZzBuildHookGOT((zz_ptr_t)name, target_ptr, NULL, pre_call_ptr, post_call_ptr);
    }

    ZzHookFunctionEntry *entry = ZzFindHookFunctionEntry((zz_ptr_t)name);
    // TODO: fix here
    rebind_symbols_image((void *)header, slide,
                         (struct rebinding[1]){{name, entry->on_enter_trampoline, (void **)origin_ptr}}, 1);
    return ZZ_SUCCESS;
}

ZZSTATUS ZzDisableHookGOT(const char *name) {
    intptr_t (*pub_dyld_get_image_slide)(const struct mach_header *mh);
    pub_dyld_get_image_slide         = dlsym((void *)dlopen(0, RTLD_LAZY), "_dyld_get_image_slide");
    zz_ptr_t target_ptr              = dlsym((void *)dlopen(0, RTLD_LAZY), name);
    const struct mach_header *header = _dyld_get_image_header(0);
    zz_size_t slide                  = pub_dyld_get_image_slide(header);
    ZzHookFunctionEntry *entry       = ZzFindHookFunctionEntry((zz_ptr_t)name);

    rebind_symbols_image((void *)header, slide, (struct rebinding[1]){{name, target_ptr, NULL}}, 1);
    return ZZ_SUCCESS;
}

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
//     ZzActivateStaticBinaryInstrumentationTrampoline(entry, (zz_addr_t)target_fileoff);
//     if (origin_ptr)
//         *origin_ptr = entry->on_invoke_trampoline;
//     return status;
// }
