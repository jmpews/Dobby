#include "trampoline.h"
#include <stdlib.h>

ZZSTATUS ZzBuildTrampoline(struct _ZzInterceptorBackend *self, ZzHookFunctionEntry *entry) {
    ZzPrepareTrampoline(self, entry);

    if (entry->hook_type == HOOK_TYPE_ADDRESS_PRE_POST) {
        ZzBuildEnterTrampoline(self, entry);
        ZzBuildHalfTrampoline(self, entry);
        ZzBuildInvokeTrampoline(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_FUNCTION_PRE_POST) {
        ZzBuildEnterTrampoline(self, entry);
        ZzBuildInvokeTrampoline(self, entry);
        ZzBuildLeaveTrampoline(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_FUNCTION_REPLACE) {
        ZzBuildEnterTransferTrampoline(self, entry);
        ZzBuildInvokeTrampoline(self, entry);
    }
    return ZZ_DONE;
}
