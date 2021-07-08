#pragma once

#include <mach/mach_types.h>
#include <mach/mach_vm.h>

#ifdef __cplusplus
extern "C" {
#endif

extern vm_map_t kernel_map;
extern task_t kernel_task;

#ifdef __cplusplus
}
#endif
