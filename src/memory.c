#include "memory.h"

ZZSTATUS ZzRuntimeCodePatch(zaddr address, zpointer codedata, zuint codedata_size) {
    if(!zz_vm_patch_code(address, codedata, codedata_size))
        return ZZ_FAILED;
    return ZZ_SUCCESS;
}
