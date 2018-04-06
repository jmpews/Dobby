//
// Created by z on 2018/2/11.
//

#include "backend-arm64-helper.h"

CodeSlice *arm64_code_patch(ZzARM64AssemblerWriter *arm64_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                            zz_size_t range_size) {
    CodeSlice *code_slice = NULL;
    if (range_size > 0) {
        code_slice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, arm64_writer->size);
    } else {
        code_slice = ExecuteMemoryManagerAllocateCodeSlice(emm, arm64_writer->size + 4);
    }

    if (!code_slice)
        return NULL;

    if (!MemoryPatchCode((zz_addr_t)code_slice->data, (zz_ptr_t)arm64_writer->w_start_address, arm64_writer->size)) {
        free(code_slice);
        return NULL;
    }
    return code_slice;
}

CodeSlice *arm64_relocate_code_patch(ZzARM64Relocator *relocator, ZzARM64AssemblerWriter *arm64_writer,
                                     ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size) {
    CodeSlice *code_slice = NULL;
    if (range_size > 0) {
        code_slice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, arm64_writer->size);
    } else {
        code_slice = ExecuteMemoryManagerAllocateCodeSlice(emm, arm64_writer->size + 4);
    }

    if (!code_slice)
        return NULL;

    arm64_relocator_relocate_writer(relocator, (zz_addr_t)code_slice->data);

    if (!MemoryPatchCode((zz_addr_t)code_slice->data, (zz_ptr_t)arm64_writer->w_start_address, arm64_writer->size)) {
        free(code_slice);
        return NULL;
    }
    return code_slice;
}