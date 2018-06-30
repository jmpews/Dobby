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

void trampoline_free(hook_entry_t *entry) {
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

void trampoline_prepare(InterceptorBackend *self, hook_entry_t *entry) { return; }

// double jump
void trampoline_build_for_enter_transfer(InterceptorBackend *self, hook_entry_t *entry) { return; }

void trampoline_build_for_enter(InterceptorBackend *self, hook_entry_t *entry) { return; }

void trampoline_build_for_dynamic_binary_instrumentation(InterceptorBackend *self, hook_entry_t *entry) { return; }

void trampoline_build_for_invoke(InterceptorBackend *self, hook_entry_t *entry) { return; }

void trampoline_build_for_leave(InterceptorBackend *self, hook_entry_t *entry) { return; }

void trampoline_active(InterceptorBackend *self, hook_entry_t *entry) { return; }