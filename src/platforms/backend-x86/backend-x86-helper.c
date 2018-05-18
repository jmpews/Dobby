//
// Created by z on 2018/2/11.
//

#include "backend-x86-helper.h"

CodeSlice *x86_code_patch(X86AssemblerWriter *x86_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                          zz_size_t range_size) {
    return NULL;
}

CodeSlice *x86_relocate_code_patch(X86Relocator *relocator, X86AssemblerWriter *x86_writer, ExecuteMemoryManager *emm,
                                   zz_addr_t target_addr, zz_size_t range_size) {
    return NULL;
}