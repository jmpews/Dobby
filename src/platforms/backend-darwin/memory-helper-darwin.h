#ifndef platforms_backend_darwin_memory_helper_darwin_h
#define platforms_backend_darwin_memory_helper_darwin_h

#include "core.h"
#include "hookzz.h"
#include "memory_manager.h"
#include "std_kit/std_kit.h"

#include "mach_vm.h"
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>

#define darwin_memory_helper_cclass(member) cclass(darwin_memory_helper, member)

int darwin_memory_helper_cclass(get_page_size)();

void darwin_memory_helper_cclass(get_memory_info)(void *address, vm_prot_t *prot, vm_inherit_t *inherit);

void darwin_memory_helper_cclass(set_page_permission)(void *address, int prot, int n);

#endif