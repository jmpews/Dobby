
#include "backend-arm-helper.h"

#include <stdlib.h>

CodeSlice *zz_thumb_code_patch(ZzThumbAssemblerWriter *thumb_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                                 zz_size_t range_size) {
    CodeSlice *codeslice = NULL;
    if (range_size > 0) {
        codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, thumb_writer->size + 4);
    } else {
        codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, thumb_writer->size + 4);
    }
    if (!codeslice)
        return NULL;

    if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)thumb_writer->start_address, thumb_writer->size)) {
        free(codeslice);
        return NULL;
    }
    return codeslice;
}

CodeSlice *zz_thumb_relocate_code_patch(ZzThumbRelocator *relocator, ZzThumbAssemblerWriter *thumb_writer,
                                          ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size) {
    CodeSlice *codeslice = NULL;
    if (range_size > 0) {
        codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, thumb_writer->size + 4);
    } else {
        codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, thumb_writer->size + 4);
    }
    if (!codeslice)
        return NULL;

    zz_thumb_relocator_relocate_writer(relocator, (zz_addr_t)codeslice->data);

    if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)thumb_writer->start_address, thumb_writer->size)) {

        free(codeslice);
        return NULL;
    }
    return codeslice;
}

CodeSlice *arm_code_patch(ARMAssemblerWriter *arm_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                               zz_size_t range_size) {
    CodeSlice *codeslice = NULL;
    if (range_size > 0) {
        codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, arm_writer->size + 4);
    } else {
        codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, arm_writer->size + 4);
    }
    if (!codeslice)
        return NULL;

    if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)arm_writer->start_address, arm_writer->size)) {
        free(codeslice);
        return NULL;
    }
    return codeslice;
}

CodeSlice *arm_relocate_code_patch(ARMRelocator *relocator, ARMAssemblerWriter *arm_writer,
                                        ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size) {
    CodeSlice *codeslice = NULL;
    if (range_size > 0) {
        codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, arm_writer->size + 4);
    } else {
        codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, arm_writer->size + 4);
    }
    if (!codeslice)
        return NULL;

    arm_relocator_relocate_writer(relocator, (zz_addr_t)codeslice->data);

    if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)arm_writer->start_address, arm_writer->size)) {
        free(codeslice);
        return NULL;
    }
    return codeslice;
}
