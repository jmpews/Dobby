//
// Created by z on 2018/2/11.
//

#include "backend-arm64-helper.h"

CodeSlice *arm64_code_patch(ARM64AssemblerWriter *arm64_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                            zz_size_t range_size) {
    CodeSlice *codeslice = NULL;
    if (range_size > 0) {
        codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, arm64_writer->size);
    } else {
        codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, arm64_writer->size + 4);
    }

    if (!codeslice)
        return NULL;

    if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)arm64_writer->start_address, arm64_writer->size)) {
        free(codeslice);
        return NULL;
    }
    return codeslice;
}

CodeSlice *arm64_relocate_code_patch(ARM64Relocator *relocator, ARM64AssemblerWriter *arm64_writer,
                                     ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size) {
    CodeSlice *codeslice = NULL;
    if (range_size > 0) {
        codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, arm64_writer->size);
    } else {
        codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, arm64_writer->size + 4);
    }

    if (!codeslice)
        return NULL;

    arm64_relocator_relocate_writer(relocator, (zz_addr_t)codeslice->data);

    if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)arm64_writer->start_address, arm64_writer->size)) {
        free(codeslice);
        return NULL;
    }
    return codeslice;
}