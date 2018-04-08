#include "trampoline.h"
#include <stdlib.h>

void TrampolineBuildAll(struct _InterceptorBackend *self, HookEntry *entry) {
if (entry->hook_type == HOOK_TYPE_FUNCTION_via_PRE_POST) {
        TrampolinePrepare(self, entry);
        TrampolineBuildForEnter(self, entry);
        TrampolineBuildForInvoke(self, entry);
        TrampolineBuildForLeave(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
        TrampolinePrepare(self, entry);
        TrampolineBuildForEnterTransfer(self, entry);
        TrampolineBuildForInvoke(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_FUNCTION_via_GOT) {
        TrampolineBuildForEnter(self, entry);
        TrampolineBuildForLeave(self, entry);
    } else if (entry->hook_type == HOOK_TYPE_DBI) {
        TrampolinePrepare(self, entry);
        TrampolineBuildForDynamicBinaryInstrumentation(self, entry);
        TrampolineBuildForInvoke(self, entry);
    }
    return;
}
