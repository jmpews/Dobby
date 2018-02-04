#include "trampoline.h"
#include <stdlib.h>

ZZSTATUS ZzBuildTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    if (entry->hook_type == HOOK_TYPE_ADDRESS_PRE_POST) {
        ZzPrepareTrampoline(self, entry);
        ZzBuildEnterTrampoline(self, entry);
        ZzBuildHalfTrampoline(self, entry);
        ZzBuildInvokeTrampoline(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
        ZzPrepareTrampoline(self, entry);
        ZzBuildEnterTrampoline(self, entry);
        ZzBuildInvokeTrampoline(self, entry);
        ZzBuildLeaveTrampoline(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
        ZzPrepareTrampoline(self, entry);
        ZzBuildEnterTransferTrampoline(self, entry);
        ZzBuildInvokeTrampoline(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
        ZzBuildEnterTrampoline(self, entry);
        ZzBuildLeaveTrampoline(self, entry);
    }
    return ZZ_DONE;
}
