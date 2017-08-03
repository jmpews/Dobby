/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <stdlib.h>

#include "interceptor.h"

// for: ZZEnableHook
#include "writer.h"

#if defined(__x86_64__)
#elif defined(__arm64__)
#include "platforms/arm64/thunker.h"
#endif

#define ZZHOOKENTRIES_DEFAULT 100
ZZInterceptor *g_interceptor;
ZZHookFunctionEntrySet *g_func_entries;
ZZInterceptorCenter *g_intercepter_center;

ZZSTATUS ZZInitialize(void) {
    if (NULL == g_interceptor) {
        g_interceptor = (ZZInterceptor *) malloc(sizeof(ZZInterceptor));
        g_func_entries =
                (ZZHookFunctionEntrySet *) malloc(sizeof(ZZHookFunctionEntrySet));
        g_intercepter_center =
                (ZZInterceptorCenter *) malloc(sizeof(ZZInterceptorCenter));

        g_interceptor->func_entries = g_func_entries;
        g_interceptor->intercepter_center = g_intercepter_center;

        g_func_entries->capacity = ZZHOOKENTRIES_DEFAULT;
        g_func_entries->entries = (ZZHookFunctionEntry **) malloc(
                sizeof(ZZHookFunctionEntry *) * g_func_entries->capacity);
        g_func_entries->size = 0;

        ZZInitializeThunk();
        return ZZ_DONE_INIT;
    }
    return ZZ_ALREADY_INIT;
}

/*
  TODO:
  bad code?
  not use the struct `ZZCodeSlice`.
 */
ZZSTATUS ZZInitializeThunk(void) {
    ZZInterceptor *interceptor = g_interceptor;
    zsize codeslice_size = 256;
    ZZWriter *writer;
    ZZCodeSlice *p;

    /*
      must be first!!!!
      build leave thunk
    */
    p = ZZAllocatorNewCodeSlice(codeslice_size);
    if (!p) {
        Serror("alloc codeslice error!");
        return ZZ_UNKOWN;
    }
    writer = ZZNewWriter(p->data);
    zz_build_leave_thunk(writer);
    make_page_executable(writer->base, writer->pc - writer->base);
    interceptor->leave_thunk = p->data;
    free(writer);

    /* build enter thunk */
    p = ZZAllocatorNewCodeSlice(codeslice_size);
    if (!p) {
        Serror("alloc codeslice error!");
        return ZZ_UNKOWN;
    }
    writer = ZZNewWriter(p->data);
    zz_build_enter_thunk(writer);
    make_page_executable(writer->base, writer->pc - writer->base);
    interceptor->enter_thunk = p->data;
    free(writer);
    return ZZ_DONE;
}

ZZHookFunctionEntry *FindHookEntry(zpointer target_ptr) {
    int i;
    for (i = 0; i < g_func_entries->size; ++i) {
        if ((g_func_entries->entries)[i] &&
            target_ptr == (g_func_entries->entries)[i]->target_ptr) {
            return (g_func_entries->entries)[i];
        }
    }
    return NULL;
}

static ZZHookFunctionEntry *AddHookEntry(ZZHookFunctionEntry *entry) {
    if (g_func_entries->size >= g_func_entries->capacity) {
        zpointer p = (ZZHookFunctionEntry *) realloc(
                g_func_entries->entries,
                sizeof(ZZHookFunctionEntry) * (g_func_entries->capacity) * 2);
        if (NULL == p) {
            return NULL;
        }
        g_func_entries->capacity = g_func_entries->capacity * 2;
        g_func_entries->entries = p;
    }
    g_func_entries->entries[g_func_entries->size++] = entry;
    return entry;
}

ZZHookFunctionEntry *ZZNewHookFunctionEntry(zpointer target_ptr) {
    ZZHookFunctionEntry *entry;
    ZZTrampoline *on_invoke_trampoline;
    entry = (ZZHookFunctionEntry *) malloc(sizeof(ZZHookFunctionEntry));

    entry->id = g_func_entries->size;
    entry->isEnabled = 0;
    entry->target_ptr = target_ptr;
    entry->interceptor = g_interceptor;
    entry->old_prologue.address = target_ptr;

    /*
        key function.
     */
    // entry->on_invoke_trampoline = ZZBuildTrampoline(target_ptr,
    // &(entry->old_prologue.size), &(entry->old_prologue.data));
    ZZBuildTrampoline(entry);

    AddHookEntry(entry);
    return entry;
}

ZZSTATUS ZZActiveHookEnterTrampoline(ZZHookFunctionEntry *entry) {
    zpointer target_ptr = entry->target_ptr;
    ZZInterceptor *interceptor = entry->interceptor;

    // make_page_writable(target_ptr, entry->old_prologue.size);

    zpointer code_data = (void *) malloc(256);
    ZZWriter *writer = ZZNewWriter(code_data);
    WriterPutAbsJmp(writer, entry->on_enter_trampoline);
    // make_page_executable(target_ptr, entry->old_prologue.size);
    memory_patch_code(target_ptr, code_data, writer->size);
    free(writer);
    return ZZ_DONE_HOOK;
}

ZZSTATUS ZZBuildHook(zpointer target_ptr, zpointer fake_ptr,
                     zpointer *origin_ptr, zpointer pre_call_ptr, zpointer post_call_ptr) {

    ZZSTATUS status = ZZ_DONE_HOOK;
    // check g_intercepter is initialize ?
    if (NULL == g_interceptor) {
        Serror("interpeptor need to be initialize !"); exit(1);
        status = ZZ_NEED_INIT;
        return status;
    }
    do {

        // check is already hooked ?
        zpointer p = FindHookEntry(target_ptr);
        if (NULL != p) {
            status = ZZ_ALREADY_HOOK;
            break;
        }
        ZZHookFunctionEntry *entry = ZZNewHookFunctionEntry(target_ptr);
        if (NULL == entry) {
            Xerror("build func-entry faild at %p", target_ptr);
            break;
        }

        entry->replace_call = fake_ptr;
        entry->pre_call = pre_call_ptr;
        entry->post_call = post_call_ptr;

        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;

    } while (0);
    return status;
}

ZZSTATUS ZZEnableHook(zpointer target_ptr) {
    ZZSTATUS status = ZZ_DONE_ENABLE;
    // check is already hooked ?
    ZZHookFunctionEntry *entry = FindHookEntry(target_ptr);

    if (NULL == entry) {
        status = ZZ_NO_BUILD_HOOK;
        Xinfo("[!] %p not build hook!", target_ptr);
        return status;
    }

    if (entry->isEnabled) {
        status = ZZ_ALREADY_ENABLED;
        Xinfo("[!] %p already enable!", target_ptr);
        return status;
    }

    ZZActiveHookEnterTrampoline(entry);
    return ZZ_DONE_HOOK;
}