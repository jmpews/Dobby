#include "memory.h"

ZZSTATUS ZzRuntimeCodePatch(zaddr address, zpointer codedata, zuint codedata_size)
{
    if (!ZzMemoryPatchCode(address, codedata, codedata_size))
        return ZZ_FAILED;
    return ZZ_SUCCESS;
}


// #include "zzdeps/common/debugbreak.h"
// #if defined(_WIN32)

// #elif defined(__APPLE__)
// #include "platforms/darwin/memory-darwin.h"
// #include "zzdeps/darwin/memory-utils-darwin.h"
// #endif
