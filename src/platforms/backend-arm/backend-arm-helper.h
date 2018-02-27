#ifndef platforms_backend_arm_backend_arm_helper
#define platforms_backend_arm_backend_arm_helper

#include "hookzz.h"
#include "kitzz.h"

#include "allocator.h"
#include "interceptor.h"
#include "thunker.h"
#include "tools.h"

#include "platforms/arch-arm/relocator-arm.h"
#include "platforms/arch-arm/relocator-thumb.h"
#include "platforms/arch-arm/writer-arm.h"
#include "platforms/arch-arm/writer-thumb.h"

ZzCodeSlice *zz_thumb_code_patch(ZzThumbAssemblerWriter *thumb_writer, ZzAllocator *allocator, zz_addr_t target_addr,
                                 zz_size_t range_size);

ZzCodeSlice *zz_thumb_relocate_code_patch(ZzThumbRelocator *thumb_relocator, ZzThumbAssemblerWriter *thumb_writer,
                                          ZzAllocator *allocator, zz_addr_t target_addr, zz_size_t range_size);

ZzCodeSlice *zz_arm_code_patch(ZzARMAssemblerWriter *arm_writer, ZzAllocator *allocator, zz_addr_t target_addr,
                               zz_size_t range_size);

ZzCodeSlice *zz_arm_relocate_code_patch(ZzARMRelocator *relocator, ZzARMAssemblerWriter *arm_writer,
                                        ZzAllocator *allocator, zz_addr_t target_addr, zz_size_t range_size);

#endif