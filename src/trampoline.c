//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#include <assert.h>

#include "trampoline.h"

/*
    TODO:
    bad? or like writer.h

    #include "writer.h"
    and in the writer.h,

    ```
    #if defined(__x86_64__)
    #include "platforms/x86/writer.h"
    #elif defined(__arm64__)
    #include "platforms/arm64/writer.h"
    #endif
    ```
 */
#if defined(__x86_64__)
#elif defined(__arm64__)
#include "platforms/arm64/relocator.h"
#include "platforms/arm64/thunker.h"
#endif

/*
    Before All:
    
 */
ZZSTATUS ZzBuildInvokeTrampoline(ZzHookFunctionEntry *entry)
{
    zbyte temp_codeslice_data[256];
    ZzWriter *backup_writer, *relocate_writer;
    ZzCodeSlice *p;
    ZzInterceptor *interceptor;
    ZZSTATUS status;

    backup_writer = ZzNewWriter(entry->origin_prologue.data);
    relocate_writer = ZzNewWriter(temp_codeslice_data);

    relocator_build_invoke_trampoline(entry, backup_writer,
                                      relocate_writer);

    WriterPutAbsJump(relocate_writer,
                    entry->target_ptr +
                        (zuint)(backup_writer->pc - backup_writer->base));

    status = ZZ_FAILED;
    do
    {
        p = ZzAllocatorNewCodeSlice(relocate_writer->size); // @common-function
        if (!p->data || !p->size)
            break;

        if (entry->hook_type == HOOK_ADDRESS_TYPE && entry->target_end_ptr)
        {
            // update caller_half_ret_addr
            entry->caller_half_ret_addr += (zaddr)p->data;
        }

        if (!zz_vm_patch_code((zaddr)p->data, temp_codeslice_data, relocate_writer->size))
            break;
        entry->on_invoke_trampoline = p->data;

        entry->origin_prologue.size = backup_writer->pc - backup_writer->base;
        assert(entry->origin_prologue.size == backup_writer->size);
        status = ZZ_SUCCESS;
    } while (0);

    free(backup_writer);
    free(relocate_writer);
    return status;
}

ZZSTATUS ZzBuildEnterTrampoline(ZzHookFunctionEntry *entry)
{
    zbyte temp_codeslice_data[256];
    ZzWriter *writer;
    ZzCodeSlice *p;
    ZzInterceptor *interceptor;
    ZZSTATUS status;

    interceptor = entry->interceptor;
    writer = ZzNewWriter(temp_codeslice_data);

    thunker_build_enter_trapoline(writer, (zpointer)entry,
                                  (zpointer)interceptor->enter_thunk); // @common-function

    status = ZZ_FAILED;
    do
    {
        p = ZzAllocatorNewNearCodeSlice((zaddr)entry->target_ptr, WriterNearJumpRangeSize(), writer->size); // @common-function
        if(!p) {
            p = ZzAllocatorNewCodeSlice(writer->size); // @common-funciton
            entry->isNearJump = false;
        } else {
            entry->isNearJump = true;
        }
        if (!p->data || !p->size)
            break;
        if (!zz_vm_patch_code((zaddr)p->data, temp_codeslice_data, writer->size))
            break;
        entry->on_enter_trampoline = p->data;
        status = ZZ_SUCCESS;
    } while (0);

    free(writer);
    return status;
}

ZZSTATUS ZzBuildLeaveTrampoline(ZzHookFunctionEntry *entry)
{
    zbyte temp_codeslice_data[256];
    ZzWriter *writer;
    ZzCodeSlice *p;
    ZzInterceptor *interceptor;
    ZZSTATUS status;

    interceptor = entry->interceptor;
    writer = ZzNewWriter(temp_codeslice_data);

    thunker_build_leave_trapoline(writer, (zpointer)entry,
                                  (zpointer)interceptor->leave_thunk);

    status = ZZ_FAILED;
    do
    {
        p = ZzAllocatorNewCodeSlice(writer->size); // @common-function
        if (!p->data || !p->size)
            break;
        if (!zz_vm_patch_code((zaddr)p->data, temp_codeslice_data, writer->size))
            break;
        entry->on_leave_trampoline = p->data;
        status = ZZ_SUCCESS;
    } while (0);

    free(writer);
    return ZZ_DONE;
}

ZZSTATUS ZzBuildHalfTrampoline(ZzHookFunctionEntry *entry)
{
    zbyte temp_codeslice_data[256];
    ZzWriter *writer;
    ZzCodeSlice *p;
    ZzInterceptor *interceptor;
    ZZSTATUS status;

    interceptor = entry->interceptor;
    writer = ZzNewWriter(temp_codeslice_data);

    thunker_build_half_trapoline(writer, (zpointer)entry,
                                 (zpointer)interceptor->half_thunk);

    status = ZZ_FAILED;
    do
    {
        p = ZzAllocatorNewCodeSlice(writer->size); // @common-function
        if (!p->data || !p->size)
            break;
        if (!zz_vm_patch_code((zaddr)p->data, temp_codeslice_data, writer->size))
            break;
        entry->on_half_trampoline = p->data;
        status = ZZ_SUCCESS;
    } while (0);

    free(writer);
    return ZZ_DONE;
}

ZZSTATUS ZzBuildTrampoline(ZzHookFunctionEntry *entry)
{
    ZzBuildEnterTrampoline(entry);

    if (entry->hook_type == HOOK_ADDRESS_TYPE)
    {
        ZzBuildHalfTrampoline(entry);
        ZzBuildInvokeTrampoline(entry);
    }
    else
    {
        ZzBuildInvokeTrampoline(entry);
        ZzBuildLeaveTrampoline(entry);
    }

    return ZZ_DONE;
}
