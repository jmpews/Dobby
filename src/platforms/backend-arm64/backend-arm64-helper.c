//
// Created by z on 2018/2/11.
//

#include "backend-arm64-helper.h"


ZzCodeSlice *zz_arm64_code_patch(ZzARM64AssemblerWriter *arm64_writer, ZzAllocator *allocator, zz_addr_t target_addr,
                                 zz_size_t range_size) {
    ZzCodeSlice *code_slice = NULL;
    if (range_size > 0) {
        code_slice = ZzNewNearCodeSlice(allocator, target_addr, range_size, arm64_writer->size);
    } else {
        code_slice = ZzNewCodeSlice(allocator, arm64_writer->size + 4);
    }

    if (!code_slice)
        return NULL;

    if (!ZzMemoryPatchCode((zz_addr_t)code_slice->data, (zz_addr_t )arm64_writer->w_start_address, arm64_writer->size)) {
        free(code_slice);
        return NULL;
    }
    return code_slice;
}

ZzCodeSlice *zz_arm64_relocate_code_patch(ZzARM64Relocator *relocator, ZzARM64AssemblerWriter *arm64_writer,
                                          ZzAllocator *allocator, zz_addr_t target_addr, zz_size_t range_size) {
    ZzCodeSlice *code_slice = NULL;
    if (range_size > 0) {
        code_slice = ZzNewNearCodeSlice(allocator, target_addr, range_size, arm64_writer->size);
    } else {
        code_slice = ZzNewCodeSlice(allocator, arm64_writer->size + 4);
    }

    if (!code_slice)
        return NULL;

    zz_arm64_relocator_relocate_writer(relocator, (zz_addr_t)code_slice->data);

    if (!ZzMemoryPatchCode((zz_addr_t)code_slice->data, (zz_ptr_t )arm64_writer->w_start_address, arm64_writer->size)) {
        free(code_slice);
        return NULL;
    }
    return code_slice;
}