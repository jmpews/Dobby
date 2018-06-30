#ifndef platforms_backend_x86_backend_x86_helper
#define platforms_backend_x86_backend_x86_helper

#include "hookzz.h"
#include "zkit.h"

#include "memory.h"
#include "interceptor.h"

#include "platforms/arch-x86/relocator-x86.h"
#include "platforms/arch-x86/writer-x86.h"

CodeSlice *x86_code_patch(X86AssemblerWriter *x86_writer, ExecuteMemoryManager *emm, zz_addr_t target_addr,
                            zz_size_t range_size);

CodeSlice *x86_relocate_code_patch(X86Relocator *relocator, X86AssemblerWriter *x86_writer,
                                     ExecuteMemoryManager *emm, zz_addr_t target_addr, zz_size_t range_size);

#endif