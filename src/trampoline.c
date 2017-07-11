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
#endif

void relocator_build_invoke_trampoline(zpointer target_addr, ZZWriter *backup_writer, ZZWriter *relocate_writer) {
    bool finished = false;
    zpointer code_addr = target_addr;
    Instruction *ins;
    
    do {
        ins = relocator_read_one(code_addr, backup_writer, relocate_writer);
        code_addr += ins->size;
        free(ins);
        if((code_addr - target_addr) >= JMP_METHOD_SIZE) {
            finished = true;
        }
    } while(!finished);

    // zpointer target_back_addr;
    // target_back_addr = target_addr + backup_writer->pc - backup_writer->base

    // writer_put_ldr_reg_imm(relocate_writer, ARM64_REG_X16, (zuint)0x8);
    // writer_put_br_reg(relocate_writer, ARM64_REG_X16);
    // writer_put_bytes(relocate_writer, (zpointer)&target_back_addr, sizeof(zpointer));
}


// ZZTrampoline *ZZBuildInovkeTrampoline(zpointer target_ptr, uint8_t *read_size, zpointer read_backup)
// {
//     zsize codeslice_size = 256;
//     ZZTrampoline *trampoline = (ZZTrampoline *)malloc(sizeof(ZZTrampoline));
//     ZZCodeSlice *p = ZZAllocatorNewCodeSlice(codeslice_size);

//     if(!p) {
//         Serror("alloc codeslice error!");
//         return NULL;
//     }

//     trampoline->codeslice = p;
//     ZZWriter backup_writer, relocate_writer;
    
//     backup_writer.codedata = read_backup;
//     backup_writer.base = read_backup;
//     backup_writer.pc = read_backup;
//     backup_writer.size = 0;

//     relocate_writer.codedata  = p->data;
//     relocate_writer.base = p->data;
//     relocate_writer.pc = p->data;
//     relocate_writer.size = 0;


//     *read_size = backup_writer.pc - backup_writer.base;
//     assert(*read_size == backup_writer.size);

//     return trampoline;
// }

ZZSTATUS ZZBuildInvokeTrampoline(ZZHookFunctionEntry *entry) {
    zsize codeslice_size = 256;
    ZZCodeSlice *p = ZZAllocatorNewCodeSlice(codeslice_size);
    if(!p) {
        Serror("alloc codeslice error!");
        return ZZ_UNKOWN;
    }
    entry->on_invoke_trampoline = p->data;
    ZZWriter *backup_writer, *relocate_writer;
    
    backup_writer = ZZNewWriter(entry->old_prologue.data);
    relocate_writer = ZZNewWriter(entry->on_invoke_trampoline);

    relocator_build_invoke_trampoline(entry->target_ptr, backup_writer, relocate_writer);

    WriterPutAbsJmp(relocate_writer, entry->target_ptr + (zuint)(backup_writer->pc - backup_writer->base));

    make_page_executable(relocate_writer->base, relocate_writer->pc - relocate_writer->base);

    entry->old_prologue.size = backup_writer->pc - backup_writer->base;
    assert(entry->old_prologue.size  == backup_writer->size);
    return ZZ_DONE;
}

ZZSTATUS ZZBuildTrampoline(ZZHookFunctionEntry *entry) {
    ZZBuildInvokeTrampoline(entry);
    return ZZ_DONE;
}

// void ZZActiveTrampoline()