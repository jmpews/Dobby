#include "trampoline.h"
#include <stdlib.h>

ZZSTATUS ZzBuildTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    ZzPrepareTrampoline(self, entry);

    if (entry->hook_type == HOOK_ADDRESS_TYPE) {
        ZzBuildEnterTrampoline(self, entry);
        ZzBuildHalfTrampoline(self, entry);
        ZzBuildInvokeTrampoline(self, entry);
    } else if (entry->hook_type == HOOK_FUNCTION_TYPE) {
        // if hook is simple hook, so just build invoke trampoline and just jump to it.
        if (entry->pre_call || entry->post_call) {
            ZzBuildEnterTrampoline(self, entry);
            ZzBuildInvokeTrampoline(self, entry);
            ZzBuildLeaveTrampoline(self, entry);
        } else {
            ZzBuildInvokeTrampoline(self, entry);
        }
    }
    return ZZ_DONE;
}
