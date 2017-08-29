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
#include "writer.h"
#include "stack.h"
#include "thunker.h"
#include "trampoline.h"
#include "thread.h"

#include "zzdeps/zz.h"

#define ZzHOOKENTRIES_DEFAULT 100
ZzInterceptor *g_interceptor = NULL;

ZZSTATUS ZzInitializeInterceptor(void)
{
    ZzInterceptor *interceptor = g_interceptor;
    ZzHookFunctionEntrySet *hook_function_entry_set;
    ZzInterceptorCenter intercepter_center;
    
    if (NULL == interceptor)
    {
        interceptor = (ZzInterceptor *)malloc(sizeof(ZzInterceptor));

        hook_function_entry_set = &(interceptor->hook_function_entry_set);
        intercepter_center = interceptor->intercepter_center;

        hook_function_entry_set->capacity = ZzHOOKENTRIES_DEFAULT;
        hook_function_entry_set->entries = (ZzHookFunctionEntry **)malloc(
            sizeof(ZzHookFunctionEntry *) * hook_function_entry_set->capacity);
        if(!hook_function_entry_set->entries) {
            return ZZ_FAILED;
        }
        hook_function_entry_set->size = 0;

        g_interceptor = interceptor;
        interceptor->allocator = ZzNewAllocator();
        ZzBuildThunk();
        return ZZ_DONE_INIT;
    }
    return ZZ_ALREADY_INIT;
}

ZZSTATUS ZzBuildThunk(void)
{
    ZzInterceptor *interceptor = g_interceptor;
    if(!interceptor)
        return ZZ_FAILED;
    zbyte temp_codeslice_data[256];
    ZzWriter *writer;
    ZzCodeSlice *codeslice;
    ZZSTATUS status;

    status = ZZ_FAILED;
    do
    {
        writer = ZzWriterNewWriter(temp_codeslice_data); // @common-function
        ZzThunkerBuildLeaveThunk(writer);              // @common-function

        // bad code ! lost `ZzCodeSlice` pointer.
        codeslice = ZzNewCodeSlice(interceptor->allocator, writer->size); // @common-function
        if (!codeslice || !codeslice->data || !codeslice->size)
            break;
        if (!ZzMemoryPatchCode((zaddr)codeslice->data, temp_codeslice_data, writer->size)) // @common-function
            break;
        interceptor->leave_thunk = codeslice->data;
        free(writer);

        writer = ZzWriterNewWriter(temp_codeslice_data); // @common-function
        ZzThunkerBuildHalfThunk(writer);               // @common-function

        // bad code ! lost `ZzCodeSlice` pointer.
        codeslice = ZzNewCodeSlice(interceptor->allocator, writer->size); // @common-function
        if (!codeslice || !codeslice->data || !codeslice->size)
            break;
        if (!ZzMemoryPatchCode((zaddr)codeslice->data, temp_codeslice_data, writer->size)) // @common-function
            break;
        interceptor->half_thunk = codeslice->data;
        free(writer);

        writer = ZzWriterNewWriter(temp_codeslice_data);
        ZzThunkerBuildEnterThunk(writer); // @common-function

        // bad code ! lost `ZzCodeSlice` pointer.
        codeslice = ZzNewCodeSlice(interceptor->allocator, writer->size);
        if (!codeslice || !codeslice->data || !codeslice->size)
            break;
        if (!ZzMemoryPatchCode((zaddr)codeslice->data, temp_codeslice_data, writer->size))
            break;
        interceptor->enter_thunk = codeslice->data;
        free(writer);
        status = ZZ_SUCCESS;
    } while (0);
    return status;
}

ZzHookFunctionEntry *ZzFindHookFunctionEntry(zpointer target_ptr)
{
    ZzInterceptor *interceptor = g_interceptor;
    if(!interceptor)
        return NULL;

    ZzHookFunctionEntrySet *hook_function_entry_set = &(interceptor->hook_function_entry_set);

    for (int i = 0; i < hook_function_entry_set->size; ++i)
    {
        if ((hook_function_entry_set->entries)[i] &&
            target_ptr == (hook_function_entry_set->entries)[i]->target_ptr)
        {
            return (hook_function_entry_set->entries)[i];
        }
    }
    return NULL;
}

bool ZzAddHookFunctionEntry(ZzHookFunctionEntry *entry)
{
    ZzInterceptor *interceptor = g_interceptor;
    if(!interceptor)
        return false;

    ZzHookFunctionEntrySet *hook_function_entry_set = &(interceptor->hook_function_entry_set);

    if (hook_function_entry_set->size >= hook_function_entry_set->capacity)
    {
        ZzHookFunctionEntry **entries = (ZzHookFunctionEntry **)realloc(
            hook_function_entry_set->entries,
            sizeof(ZzHookFunctionEntry *) * hook_function_entry_set->capacity * 2);
        if (!entries)
            return false;

        hook_function_entry_set->capacity = hook_function_entry_set->capacity * 2;
        hook_function_entry_set->entries = entries;
    }
    hook_function_entry_set->entries[hook_function_entry_set->size++] = entry;
    return true;
}

void ZzInitializeHookFunctionEntry(ZzHookFunctionEntry *entry, int hook_type, zpointer target_ptr, zpointer target_end_ptr, zpointer replace_call, PRECALL pre_call, HALFCALL half_call, POSTCALL post_call)
{
    ZzInterceptor *interceptor = g_interceptor;
    ZzHookFunctionEntrySet *hook_function_entry_set = &(interceptor->hook_function_entry_set);
    
    entry->hook_type = hook_type;
    entry->id = hook_function_entry_set->size;
    entry->isEnabled = 0;
    entry->interceptor = interceptor;

    entry->target_ptr = target_ptr;
    entry->target_end_ptr = target_end_ptr;

    entry->replace_call = replace_call;
    entry->pre_call = (zpointer)pre_call;
    entry->half_call = (zpointer)half_call;
    entry->post_call = (zpointer)post_call;

    entry->on_enter_trampoline = NULL;
    entry->on_invoke_trampoline = NULL;
    entry->on_half_trampoline = NULL;
    entry->on_leave_trampoline = NULL;

    entry->origin_prologue.address = target_ptr;

    entry->thread_local_key = ZzThreadNewThreadLocalKeyPtr();

    ZzBuildTrampoline(entry);
    ZzAddHookFunctionEntry(entry);
}

ZZSTATUS ZzActiveHookFunctionEntry(ZzHookFunctionEntry *entry)
{
    zpointer target_ptr = entry->target_ptr;
    ZzInterceptor *interceptor = entry->interceptor;
    zbyte temp_codeslice_data[256];

    ZzWriter *writer = ZzWriterNewWriter(temp_codeslice_data);
    if(entry->isNearJump) {
        ZzWriterPutNearJump(writer, (zsize)((zaddr)entry->on_enter_trampoline - (zaddr)entry->target_ptr));
    } else {
        Xdebug("target %p abs jump to %p", entry->target_ptr, entry->on_enter_trampoline);
        ZzWriterPutAbsJump(writer, entry->on_enter_trampoline); // @common-function
    }
    ZzMemoryPatchCode((zaddr)target_ptr, temp_codeslice_data, writer->size);
    free(writer);

    return ZZ_DONE_HOOK;
}

ZZSTATUS ZzBuildHook(zpointer target_ptr, zpointer replace_call_ptr,
                     zpointer *origin_ptr, PRECALL pre_call_ptr, POSTCALL post_call_ptr)
{

    ZZSTATUS status = ZZ_DONE_HOOK;
    ZzInterceptor *interceptor = g_interceptor;
    ZzHookFunctionEntrySet *hook_function_entry_set;

    if (!interceptor)
    {
        ZzInitializeInterceptor();
        if(!g_interceptor)
            return ZZ_FAILED;
    }

    interceptor = g_interceptor;
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    do
    {

        ZzHookFunctionEntry *entry;

        // check is already hooked
        if (ZzFindHookFunctionEntry(target_ptr))
        {
            status = ZZ_ALREADY_HOOK;
            break;
        }

        entry = (ZzHookFunctionEntry *)malloc(sizeof(ZzHookFunctionEntry));

        if (!entry)
        {
            Xerror("build HookFunctionEnry faild at %p", target_ptr);
            break;
        }

        
        ZzInitializeHookFunctionEntry(entry, HOOK_FUNCTION_TYPE, target_ptr, 0, replace_call_ptr, pre_call_ptr, NULL, post_call_ptr);
    
        if (origin_ptr)
            *origin_ptr = entry->on_invoke_trampoline;

    } while (0);
    return status;
}

ZZSTATUS ZzBuildHookAddress(zpointer target_start_ptr, zpointer target_end_ptr, PRECALL pre_call_ptr, HALFCALL half_call_ptr)
{

    ZZSTATUS status = ZZ_DONE_HOOK;
    ZzInterceptor *interceptor = g_interceptor;
    ZzHookFunctionEntrySet *hook_function_entry_set;

    if (!interceptor)
    {
        ZzInitializeInterceptor();
        if(!g_interceptor)
            return ZZ_FAILED;
    }

    interceptor = g_interceptor;
    hook_function_entry_set = &(interceptor->hook_function_entry_set);

    do
    {

        ZzHookFunctionEntry *entry;

        // check is already hooked
        if (ZzFindHookFunctionEntry(target_start_ptr))
        {
            status = ZZ_ALREADY_HOOK;
            break;
        }

        entry = (ZzHookFunctionEntry *)malloc(sizeof(ZzHookFunctionEntry));

        if (!entry)
        {
            Xerror("build HookFunctionEnry faild at %p", target_start_ptr);
            break;
        }

        ZzInitializeHookFunctionEntry(entry, HOOK_ADDRESS_TYPE, target_start_ptr, target_end_ptr, NULL, pre_call_ptr, half_call_ptr, NULL);

    } while (0);
    return status;
}

ZZSTATUS ZzEnableHook(zpointer target_ptr)
{
    ZZSTATUS status = ZZ_DONE_ENABLE;
    // check is already hooked ?
    ZzHookFunctionEntry *entry = ZzFindHookFunctionEntry(target_ptr);

    if (!entry)
    {
        status = ZZ_NO_BUILD_HOOK;
        Xinfo(" %p not build HookFunctionEntry!", target_ptr);
        return status;
    }

    if (entry->isEnabled)
    {
        status = ZZ_ALREADY_ENABLED;
        Xinfo("HookFunctionEntry %p already enable!", target_ptr);
        return status;
    }

    return ZzActiveHookFunctionEntry(entry);
}
