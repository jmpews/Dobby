#ifndef platforms_backend_arm_backend_arm_helper
#define platforms_backend_arm_backend_arm_helper

#include "hookzz.h"
#include "zkit.h"

#include "emm.h"
#include "interceptor.h"
#include "bridge.h"
#include "tools.h"

#include "platforms/arch-arm/relocator-arm.h"
#include "platforms/arch-arm/relocator-thumb.h"
#include "platforms/arch-arm/writer-arm.h"
#include "platforms/arch-arm/writer-thumb.h"

CodeSlice *zz_thumb_code_patch(ZzThumbAssemblerWriter *thumb_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                                 zz_size_t range_size);

CodeSlice *zz_thumb_relocate_code_patch(ZzThumbRelocator *thumb_relocator, ZzThumbAssemblerWriter *thumb_writer,
                                          ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size);

CodeSlice *zz_arm_code_patch(ZzARMAssemblerWriter *arm_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                               zz_size_t range_size);

CodeSlice *zz_arm_relocate_code_patch(ZzARMRelocator *relocator, ZzARMAssemblerWriter *arm_writer,
                                        ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size);

#endif