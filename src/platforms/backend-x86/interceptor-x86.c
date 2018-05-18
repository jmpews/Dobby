#include "interceptor-x86.h"
#include "backend-x86-helper.h"
#include "closure-bridge-x86.h"

#include "custom-bridge-handler.h"

#include <debuglog.h>
#include <stdlib.h>
#include <string.h>

#define ZZ_X86_TINY_REDIRECT_SIZE 4
#define ZZ_X86_FULL_REDIRECT_SIZE 16

InterceptorBackend *InteceptorBackendNew(ExecuteMemoryManager *emm) { return NULL; }

void TrampolineFree(HookEntry *entry) {
    if (entry->on_invoke_trampoline) {
        //TODO
    }

    if (entry->on_enter_trampoline) {
        //TODO
    }

    if (entry->on_enter_transfer_trampoline) {
        //TODO
    }

    if (entry->on_leave_trampoline) {
        //TODO
    }

    if (entry->on_invoke_trampoline) {
        //TODO
    }
    return;
}

void TrampolinePrepare(InterceptorBackend *self, HookEntry *entry) { return; }

// double jump
void TrampolineBuildForEnterTransfer(InterceptorBackend *self, HookEntry *entry) { return; }

void TrampolineBuildForEnter(InterceptorBackend *self, HookEntry *entry) { return; }

void TrampolineBuildForDynamicBinaryInstrumentation(InterceptorBackend *self, HookEntry *entry) { return; }

void TrampolineBuildForInvoke(InterceptorBackend *self, HookEntry *entry) { return; }

void TrampolineBuildForLeave(InterceptorBackend *self, HookEntry *entry) { return; }

void TrampolineActivate(InterceptorBackend *self, HookEntry *entry) { return; }