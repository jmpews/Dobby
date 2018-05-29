#include "dynamic-closure-bridge-darwin.h"
#include "closurebridge.h"

#include <CommonKit/log/log_kit.h>

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/vm_page_size.h>
#include <pthread.h>
#include <stdlib.h>

#define dynamic_closure_trampoline_template_length (7 * 4)

extern void dynamic_common_bridge_handler(RegState *rs, DynamicClosureTrampoline *cbd);

static DynamicClosureTrampolineTable *gDynamicClosureTrampolineTable;

static DynamicClosureTrampolineTable *DynamicClosureTrampolineTableAllocate(void) {
    void *mmap_page;
    long page_size;
    page_size = sysconf(_SC_PAGESIZE);

    vm_address_t data_page;
    vm_address_t trampoline_page;
    vm_address_t trampoline_page_template;
    vm_prot_t cur_prot;
    vm_prot_t max_prot;
    kern_return_t kt;
    /* Allocate two pages -- a config page and a placeholder page */
    kt = vm_allocate(mach_task_self(), &data_page, PAGE_MAX_SIZE * 2, VM_FLAGS_ANYWHERE);
    if (kt != KERN_SUCCESS) {
        COMMON_ERROR_LOG();
        return NULL;
    }

    int t = page_size / dynamic_closure_trampoline_template_length;

    // Remap the trampoline table on top of the placeholder page
    trampoline_page          = data_page + PAGE_MAX_SIZE;
    trampoline_page_template = (vm_address_t)&dynamic_closure_trampoline_table_page;
#ifdef __arm__
    // ffi_closure_trampoline_table_page can be thumb-biased on some ARM archs
    trampoline_page_template &= ~1UL;
#endif
    kt = vm_remap(mach_task_self(), &trampoline_page, PAGE_MAX_SIZE, 0x0, VM_FLAGS_OVERWRITE, mach_task_self(),
                  trampoline_page_template, FALSE, &cur_prot, &max_prot, VM_INHERIT_SHARE);
    if (kt != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), data_page, PAGE_MAX_SIZE * 2);
        return NULL;
    }

    DynamicClosureTrampolineTable *table =
        (DynamicClosureTrampolineTable *)malloc(sizeof(DynamicClosureTrampolineTable));
    table->entry           = (void *)trampoline_page;
    table->trampoline_page = (void *)trampoline_page;
    table->data_page       = (void *)data_page;
    table->used_count      = 0;
    table->free_count      = (uint16_t)t;
    return table;
}

static void DynamicClosureBridgeTrampolineTableFree(DynamicClosureTrampolineTable *table) { return; }

DynamicClosureTrampoline *DynamicClosureBridgeTrampolineAllocate(void *user_data, void *user_code) {
    long page_size                       = sysconf(_SC_PAGESIZE);
    DynamicClosureTrampolineTable *table = gDynamicClosureTrampolineTable;
    if (table == NULL || table->free_count == 0) {
        table = DynamicClosureTrampolineTableAllocate();
        if (table == NULL)
            return NULL;

        table->next = gDynamicClosureTrampolineTable;
        if (table->next != NULL) {
            table->next->prev = table;
        }
        gDynamicClosureTrampolineTable = table;
    }

    DynamicClosureTrampoline *bridgeData = (DynamicClosureTrampoline *)malloc(sizeof(DynamicClosureTrampoline));
    bridgeData->common_bridge_handler    = (void *)dynamic_common_bridge_handler;

    bridgeData->user_code           = user_code;
    bridgeData->user_data           = user_data;
    uint16_t trampoline_used_count  = gDynamicClosureTrampolineTable->used_count;
    bridgeData->redirect_trampoline = (void *)((intptr_t)gDynamicClosureTrampolineTable->trampoline_page +
                                               dynamic_closure_trampoline_template_length * trampoline_used_count);

    // bind the closure data
    uintptr_t closure_trampoine_data_address = (uintptr_t)bridgeData->redirect_trampoline - PAGE_MAX_SIZE;
    *(DynamicClosureTrampoline **)closure_trampoine_data_address = bridgeData;

    table->used_count++;
    table->free_count--;

    return bridgeData;
}

static void ClosureBridgeFree(DynamicClosureTrampoline *bridgeData) { return; }