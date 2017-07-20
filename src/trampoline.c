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
#include "writer.h"

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

ZZSTATUS ZZBuildInvokeTrampoline(ZZHookFunctionEntry *entry) {
  zsize codeslice_size = 256;
  ZZCodeSlice *p = ZZAllocatorNewCodeSlice(codeslice_size);
  if (!p) {
    Serror("alloc codeslice error!");
    return ZZ_UNKOWN;
  }
  entry->on_invoke_trampoline = p->data;
  ZZWriter *backup_writer, *relocate_writer;

  backup_writer = ZZNewWriter(entry->old_prologue.data);
  relocate_writer = ZZNewWriter(entry->on_invoke_trampoline);

  relocator_build_invoke_trampoline(entry->target_ptr, backup_writer,
                                    relocate_writer);

  WriterPutAbsJmp(relocate_writer,
                  entry->target_ptr +
                      (zuint)(backup_writer->pc - backup_writer->base));

  make_page_executable(relocate_writer->base,
                       relocate_writer->pc - relocate_writer->base);

  entry->old_prologue.size = backup_writer->pc - backup_writer->base;
  assert(entry->old_prologue.size == backup_writer->size);
  free(backup_writer);
  free(relocate_writer);
  return ZZ_DONE;
}

ZZSTATUS ZZBuildEnterTrampoline(ZZHookFunctionEntry *entry) {
  zsize codeslice_size = 256;
  ZZCodeSlice *p = ZZAllocatorNewCodeSlice(codeslice_size);
  ZZInterceptor *interceptor = entry->interceptor;
  if (!p) {
    Serror("alloc codeslice error!");
    return ZZ_UNKOWN;
  }

  entry->on_enter_trampoline = p->data;

  ZZWriter *writer;

  writer = ZZNewWriter(p->data);

  thunker_build_enter_trapoline(writer, (zpointer)entry,
                                (zpointer)interceptor->enter_thunk);

  make_page_executable(writer->base, writer->pc - writer->base);

  free(writer);
  return ZZ_DONE;
}

ZZSTATUS ZZBuildLeaveTrampoline(ZZHookFunctionEntry *entry) {
  zsize codeslice_size = 256;
  ZZCodeSlice *p = ZZAllocatorNewCodeSlice(codeslice_size);
  ZZInterceptor *interceptor = entry->interceptor;
  if (!p) {
    Serror("alloc codeslice error!");
    return ZZ_UNKOWN;
  }

  entry->on_leave_trampoline = p->data;

  ZZWriter *writer;

  writer = ZZNewWriter(p->data);

  thunker_build_leave_trapoline(writer, (zpointer)entry,
                                (zpointer)interceptor->leave_thunk);

  make_page_executable(writer->base, writer->pc - writer->base);

  free(writer);
  return ZZ_DONE;
}

ZZSTATUS ZZBuildTrampoline(ZZHookFunctionEntry *entry) {
  ZZBuildEnterTrampoline(entry);
  ZZBuildInvokeTrampoline(entry);
  ZZBuildLeaveTrampoline(entry);
  return ZZ_DONE;
}

// void ZZActiveTrampoline()
