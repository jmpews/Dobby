#include "debuglog.h"
#include <stdio.h>
#include <strings.h>

DebugLogControler gDebugLogControler;

void DebugLogControlerEnableLog() { gDebugLogControler.is_enable_log = true; }

bool DebugLogControlerIsEnableLog() { return gDebugLogControler.is_enable_log; }

bool DebugLogControlerIsEnableDebugbreak() { return gDebugLogControler.is_enable_debugbreak; }

DebugLogControler *DebugLogControlerSharedInstance(void) { return &gDebugLogControler; }

void Log_TrampolineBuildForEnterTransfer(HookEntry *entry, CodeSlice *codeslice) {
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= EnterTransferTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\ton_enter_transfer_trampoline: %p\n", entry->on_enter_transfer_trampoline);
        sprintf(buffer + strlen(buffer), "\ttrampoline_length: %ld\n", codeslice->size);
        sprintf(buffer + strlen(buffer), "\thook_entry: %p\n", (void *)entry);
        if (entry->hook_type == HOOK_TYPE_FUNCTION_via_REPLACE) {
            sprintf(buffer + strlen(buffer), "\tjump_target: replace_call(%p)\n", (void *)entry->replace_call);
        } else if (entry->hook_type == HOOK_TYPE_DBI) {
            sprintf(buffer + strlen(buffer), "\tjump_target: on_dynamic_binary_instrumentation_trampoline(%p)\n",
                    (void *)entry->on_dynamic_binary_instrumentation_trampoline);
        } else {
            sprintf(buffer + strlen(buffer), "\tjump_target: on_enter_trampoline(%p)\n",
                    (void *)entry->on_enter_trampoline);
        }
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
}

void Log_TrampolineBuildForEnter(HookEntry *entry) {
    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= EnterTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\ton_enter_trampoline: %p\n", entry->on_leave_trampoline);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
}

void Log_TrampolineBuildForInvoke(HookEntry *entry, CodeSlice *codeslice) {
    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= InvokeTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\ton_invoke_trampoline: %p\n", entry->on_invoke_trampoline);
        sprintf(buffer + strlen(buffer), "\ttrampoline_length: %ld\n", codeslice->size);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
}

void Log_TrampolineBuildForLeave(HookEntry *entry) {
    // debug log
    if (DebugLogControlerIsEnableLog()) {
        char buffer[1024] = {};
        sprintf(buffer + strlen(buffer), "\n======= LeaveTrampoline ======= \n");
        sprintf(buffer + strlen(buffer), "\ton_leave_trampoline: %p\n", entry->on_leave_trampoline);
        DEBUGLOG_COMMON_LOG("%s", buffer);
    }
}
