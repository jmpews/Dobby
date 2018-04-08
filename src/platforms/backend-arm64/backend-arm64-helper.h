#ifndef platforms_backend_arm64_backend_arm64_helper
#define platforms_backend_arm64_backend_arm64_helper

#include "hookzz.h"
#include "zkit.h"

#include "memory.h"
#include "interceptor.h"

#include "platforms/arch-arm64/relocator-arm64.h"
#include "platforms/arch-arm64/writer-arm64.h"

CodeSlice *arm64_code_patch(ARM64AssemblerWriter *arm64_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                            zz_size_t range_size);

CodeSlice *arm64_relocate_code_patch(ARM64Relocator *relocator, ARM64AssemblerWriter *arm64_writer,
                                     ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size);

#endif