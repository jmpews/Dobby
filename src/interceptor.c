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

// for: ZzEnableHook
#include "writer.h"

#include "stack.h"

// or like `writer.h`
#if defined(__x86_64__)
#elif defined(__arm64__)
#include "platforms/arm64/thunker.h"
#endif

#define ZzHOOKENTRIES_DEFAULT 100
ZzInterceptor *g_interceptor;
ZzHookFunctionEntrySet *g_hook_func_entries;
ZzInterceptorCenter *g_intercepter_center;

ZZSTATUS ZzInitialize(void)
{
    if (NULL == g_interceptor)
    {
        g_interceptor = (ZzInterceptor *)malloc(sizeof(ZzInterceptor));
        g_hook_func_entries =
            (ZzHookFunctionEntrySet *)malloc(sizeof(ZzHookFunctionEntrySet));
        g_intercepter_center =
            (ZzInterceptorCenter *)malloc(sizeof(ZzInterceptorCenter));

        g_interceptor->hook_func_entries = g_hook_func_entries;
        g_interceptor->intercepter_center = g_intercepter_center;

        g_hook_func_entries->capacity = ZzHOOKENTRIES_DEFAULT;
        g_hook_func_entries->entries = (ZzHookFunctionEntry **)malloc(
            sizeof(ZzHookFunctionEntry *) * g_hook_func_entries->capacity);
        g_hook_func_entries->size = 0;

        ZzBuildThunk();
        return ZZ_DONE_INIT;
    }
    return ZZ_ALREADY_INIT;
}

ZZSTATUS ZzBuildThunk(void)
{
    ZzInterceptor *interceptor = g_interceptor;
    zbyte temp_codeslice_data[256];
    ZzWriter *writer;
    ZzCodeSlice *p;
    ZZSTATUS status;

    status = ZZ_FAILED;
    do
    {
        writer = ZzNewWriter(temp_codeslice_data); // @common-function
        zz_build_leave_thunk(writer);              // @common-function

        // bad code ! lost `ZzCodeSlice` pointer.
        p = ZzAllocatorNewCodeSlice(writer->size); // @common-function
        if (!p->data || !p->size)
            break;
        if (!zz_vm_patch_code((zaddr)p->data, temp_codeslice_data, writer->size)) // @common-function
            break;
        interceptor->leave_thunk = p->data;
        free(writer);

        writer = ZzNewWriter(temp_codeslice_data); // @common-function
        zz_build_half_thunk(writer);               // @common-function

        // bad code ! lost `ZzCodeSlice` pointer.
        p = ZzAllocatorNewCodeSlice(writer->size); // @common-function
        if (!p->data || !p->size)
            break;
        if (!zz_vm_patch_code((zaddr)p->data, temp_codeslice_data, writer->size)) // @common-function
            break;
        interceptor->half_thunk = p->data;
        free(writer);

        writer = ZzNewWriter(temp_codeslice_data);
        zz_build_enter_thunk(writer); // @common-function

        // bad code ! lost `ZzCodeSlice` pointer.
        p = ZzAllocatorNewCodeSlice(writer->size);
        if (!p->data || !p->size)
            break;
        if (!zz_vm_patch_code((zaddr)p->data, temp_codeslice_data, writer->size))
            break;
        interceptor->enter_thunk = p->data;
        free(writer);
        status = ZZ_SUCCESS;
    } while (0);
    return status;
}

ZzHookFunctionEntry *ZzFindHookEntry(zpointer target_ptr)
{
    int i;
    for (i = 0; i < g_hook_func_entries->size; ++i)
    {
        if ((g_hook_func_entries->entries)[i] &&
            target_ptr == (g_hook_func_entries->entries)[i]->target_ptr)
        {
            return (g_hook_func_entries->entries)[i];
        }
    }
    return NULL;
}

static ZzHookFunctionEntry *ZzAddHookEntry(ZzHookFunctionEntry *entry)
{
    if (g_hook_func_entries->size >= g_hook_func_entries->capacity)
    {
        zpointer p = (ZzHookFunctionEntry *)realloc(
            g_hook_func_entries->entries,
            sizeof(ZzHookFunctionEntry) * (g_hook_func_entries->capacity) * 2);
        if (NULL == p)
        {
            return NULL;
        }
        g_hook_func_entries->capacity = g_hook_func_entries->capacity * 2;
        g_hook_func_entries->entries = p;
    }
    g_hook_func_entries->entries[g_hook_func_entries->size++] = entry;
    return entry;
}

ZzHookFunctionEntry *ZzNewHookFunctionEntry(zpointer target_ptr, zpointer target_end_ptr)
{
    ZzHookFunctionEntry *entry;
    ZzTrampoline *on_invoke_trampoline;
    entry = (ZzHookFunctionEntry *)malloc(sizeof(ZzHookFunctionEntry));

    entry->id = g_hook_func_entries->size;
    entry->isEnabled = 0;
    entry->target_ptr = target_ptr;
    entry->target_end_ptr = target_end_ptr;
    entry->interceptor = g_interceptor;

    entry->replace_call = NULL;
    entry->pre_call = NULL;
    entry->half_call = NULL;
    entry->post_call = NULL;

    entry->on_enter_trampoline = NULL;
    entry->on_invoke_trampoline = NULL;
    entry->on_half_trampoline = NULL;
    entry->on_leave_trampoline = NULL;

    entry->origin_prologue.address = target_ptr;

    return entry;
}

ZZSTATUS ZzActiveHookEnterTrampoline(ZzHookFunctionEntry *entry)
{
    zpointer target_ptr = entry->target_ptr;
    ZzInterceptor *interceptor = entry->interceptor;
    zbyte temp_codeslice_data[256];

    ZzWriter *writer = ZzNewWriter(temp_codeslice_data);
    WriterPutAbsJmp(writer, entry->on_enter_trampoline); // @common-function
    zz_vm_patch_code((zaddr)target_ptr, temp_codeslice_data, writer->size);
    free(writer);

    return ZZ_DONE_HOOK;
}

ZZSTATUS ZzBuildHook(zpointer target_ptr, zpointer fake_ptr,
                     zpointer *origin_ptr, zpointer pre_call_ptr, zpointer post_call_ptr)
{

    ZZSTATUS status = ZZ_DONE_HOOK;

    // check g_intercepter initialize
    if (NULL == g_interceptor)
    {
        Serror("interpeptor need to be initialize !");
        exit(1);
        status = ZZ_NEED_INIT;
        return status;
    }
    do
    {

        // check is already hooked
        zpointer p = ZzFindHookEntry(target_ptr);
        if (NULL != p)
        {
            status = ZZ_ALREADY_HOOK;
            break;
        }
        ZzHookFunctionEntry *entry = ZzNewHookFunctionEntry(target_ptr, 0);
        if (NULL == entry)
        {
            Xerror("build func-entry faild at %p", target_ptr);
            break;
        }

        entry->hook_type = HOOK_FUNCTION_TYPE;
        entry->replace_call = fake_ptr;
        entry->pre_call = pre_call_ptr;
        entry->post_call = post_call_ptr;

        /*
            key function.
            build trampoline for jump to thunk.
        */
        ZzBuildTrampoline(entry);

        ZzAddHookEntry(entry);

        entry->thread_local_key = ZzNewThreadLocalKey();


        
        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;

    } while (0);
    return status;
}

ZZSTATUS ZzBuildHookAddress(zpointer target_start_ptr, zpointer target_end_ptr, zpointer pre_call_ptr, zpointer half_call_ptr)
{

    ZZSTATUS status = ZZ_DONE_HOOK;

    if(!target_end_ptr && half_call_ptr) {
        Sinfo("2th arg is none, default set as next instruction.");
        target_end_ptr = target_start_ptr + 4;
    }
    // check g_intercepter initialize
    if (NULL == g_interceptor)
    {
        Serror("interpeptor need to be initialize !");
        exit(1);
        status = ZZ_NEED_INIT;
        return status;
    }
    do
    {

        // check is already hooked
        zpointer p = ZzFindHookEntry(target_start_ptr);
        if (NULL != p)
        {
            status = ZZ_ALREADY_HOOK;
            break;
        }
        ZzHookFunctionEntry *entry = ZzNewHookFunctionEntry(target_start_ptr, target_end_ptr);
        if (NULL == entry)
        {
            Xerror("build func-entry faild at %p", target_start_ptr);
            break;
        }

        entry->hook_type = HOOK_ADDRESS_TYPE;
        entry->pre_call = pre_call_ptr;
        entry->half_call = half_call_ptr;

        /*
key function.
build trampoline for jump to thunk.
*/
        ZzBuildTrampoline(entry);

        ZzAddHookEntry(entry);

        entry->thread_local_key = ZzNewThreadLocalKey();

    } while (0);
    return status;
}

ZZSTATUS ZzEnableHook(zpointer target_ptr)
{
    ZZSTATUS status = ZZ_DONE_ENABLE;
    // check is already hooked ?
    ZzHookFunctionEntry *entry = ZzFindHookEntry(target_ptr);

    if (NULL == entry)
    {
        status = ZZ_NO_BUILD_HOOK;
        Xinfo("[!] %p not build hook!", target_ptr);
        return status;
    }

    if (entry->isEnabled)
    {
        status = ZZ_ALREADY_ENABLED;
        Xinfo("[!] %p already enable!", target_ptr);
        return status;
    }

    return ZzActiveHookEnterTrampoline(entry);
}
