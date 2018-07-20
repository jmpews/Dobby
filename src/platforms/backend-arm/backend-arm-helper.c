
#include "backend-arm-helper.h"

#include <stdlib.h>

CodeSlice *thumb_code_patch(ThumbAssemblerWriter *writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                            zz_size_t range_size) {
  CodeSlice *codeslice = NULL;
  if (range_size > 0) {
    codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, writer->insns_size + 4);
  } else {
    codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, writer->insns_size + 4);
  }
  if (!codeslice)
    return NULL;

  if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)writer->insns_buffer, writer->insns_size)) {
    free(codeslice);
    return NULL;
  }
  return codeslice;
}

CodeSlice *thumb_relocate_code_patch(ThumbRelocator *relocator, ThumbAssemblerWriter *writer, ExecuteMemoryManager *emm,
                                     zz_addr_t target_addr, zz_size_t range_size) {
  CodeSlice *codeslice = NULL;
  if (range_size > 0) {
    codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, writer->insns_size + 4);
  } else {
    codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, writer->insns_size + 4);
  }
  if (!codeslice)
    return NULL;
#if 1
  thumb_relocator_relocate_writer(relocator, (zz_addr_t)codeslice->data);
#else
  thumb_relocator_double_write(relocator, (zz_addr_t)codeslice->data);
#endif

  if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)writer->insns_buffer, writer->insns_size)) {

    free(codeslice);
    return NULL;
  }
  return codeslice;
}

CodeSlice *arm_code_patch(ARMAssemblerWriter *writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                          zz_size_t range_size) {
  CodeSlice *codeslice = NULL;
  if (range_size > 0) {
    codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, writer->insns_size + 4);
  } else {
    codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, writer->insns_size + 4);
  }
  if (!codeslice)
    return NULL;

  if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)writer->insns_buffer, writer->insns_size)) {
    free(codeslice);
    return NULL;
  }
  return codeslice;
}

CodeSlice *arm_relocate_code_patch(ARMRelocator *relocator, ARMAssemblerWriter *writer, ExecuteMemoryManager *emm,
                                   zz_addr_t target_addr, zz_size_t range_size) {
  CodeSlice *codeslice = NULL;
  if (range_size > 0) {
    codeslice = ExecuteMemoryManagerAllocateNearCodeSlice(emm, target_addr, range_size, writer->insns_size + 4);
  } else {
    codeslice = ExecuteMemoryManagerAllocateCodeSlice(emm, writer->insns_size + 4);
  }
  if (!codeslice)
    return NULL;

#if 1
  arm_relocator_relocate_writer(relocator, (zz_addr_t)codeslice->data);
#else
  arm_relocator_double_write(relocator, (zz_addr_t)codeslice->data);
#endif

  if (!MemoryHelperPatchCode((zz_addr_t)codeslice->data, (zz_ptr_t)writer->insns_buffer, writer->insns_size)) {
    free(codeslice);
    return NULL;
  }
  return codeslice;
}
