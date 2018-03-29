#ifndef platforms_backend_arm64_backend_arm64_helper
#define platforms_backend_arm64_backend_arm64_helper

#include "hookzz.h"
#include "zkit.h"

#include "allocator.h"
#include "interceptor.h"
#include "thunker.h"
#include "tools.h"

#include "platforms/arch-arm64/relocator-arm64.h"
#include "platforms/arch-arm64/writer-arm64.h"

ZzCodeSlice *zz_arm64_code_patch(ZzARM64AssemblerWriter *arm64_writer, ZzAllocator *allocator, zz_addr_t target_addr,
                                 zz_size_t range_size);

ZzCodeSlice *zz_arm64_relocate_code_patch(ZzARM64Relocator *relocator, ZzARM64AssemblerWriter *arm64_writer,
                                          ZzAllocator *allocator, zz_addr_t target_addr, zz_size_t range_size);

#endif