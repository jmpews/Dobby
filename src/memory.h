#include "../include/zz.h"
#include "../include/hookzz.h"

extern zsize zz_vm_get_page_size(); // @common-function
extern zpointer zz_vm_allocate(zsize size); // @common-function
extern bool zz_vm_protect_as_executable(const zaddr address, zsize size); // @common-function
extern bool zz_vm_patch_code(const zaddr address, const zpointer codedata, zuint codedata_size); // @common-function