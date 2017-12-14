#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "PosixKit/memory/posix_memory_kit.h"

// http://renatocunha.com/blog/2015/12/msync-pointer-validity/
bool zz_posix_vm_check_address_valid_via_msync(const zz_ptr_t p) {
    int ret = 0;
    zz_size_t page_size;
    zz_ptr_t base;
    /* get the page size */
    page_size = zz_posix_vm_get_page_size();
    /* find the address of the page that contains p */
    base = (void *)((((size_t)p) / page_size) * page_size);
    /* call msync, if it returns non-zero, return FALSE */
    ret = msync(base, page_size, MS_ASYNC) != -1;
    return ret ? ret : errno != ENOMEM;
}

// ATTENTION !!!
// lldb is still catch EXC_BAD_ACCESS, without lldb is ok.
// https://www.cocoawithlove.com/2010/10/testing-if-arbitrary-pointer-is-valid.html
// https://stackoverflow.com/questions/26829119/how-to-make-lldb-ignore-exc-bad-access-exception
// ---check start---
#include <setjmp.h>
#include <signal.h>

static sigjmp_buf sigjmp_env;

void PointerReadFailedHandler(int signum) { siglongjmp(sigjmp_env, 1); }

bool zz_posix_vm_check_address_valid_via_signal(zz_ptr_t p) {
    // Set up SIGSEGV and SIGBUS handlers
    struct sigaction new_segv_action, old_segv_action;
    struct sigaction new_bus_action, old_bus_action;
    new_segv_action.sa_handler = PointerReadFailedHandler;
    new_bus_action.sa_handler  = PointerReadFailedHandler;
    sigemptyset(&new_segv_action.sa_mask);
    sigemptyset(&new_bus_action.sa_mask);
    new_segv_action.sa_flags = 0;
    new_bus_action.sa_flags  = 0;
    sigaction(SIGSEGV, &new_segv_action, &old_segv_action);
    sigaction(SIGBUS, &new_bus_action, &old_bus_action);

    // The signal handler will return us to here if a signal is raised
    if (sigsetjmp(sigjmp_env, 1)) {
        sigaction(SIGSEGV, &old_segv_action, NULL);
        sigaction(SIGBUS, &old_bus_action, NULL);
        return FALSE;
    }
    // ATTENTION !!! this function is conflict with LLDB, reason is below.
    // lldb is still catch EXC_BAD_ACCESS, without lldb is ok.
    // or you can use `zz_check_address_valid_via_mem` replace
    // https://stackoverflow.com/questions/26829119/how-to-make-lldb-ignore-exc-bad-access-exception
    char x = *(char *)p;
    return TRUE;
}

zz_size_t zz_posix_vm_get_page_size() { return getpagesize(); }

// int mprotect(void *addr, size_t len, int prot);
bool zz_posix_vm_protect(const zz_addr_t address, zz_size_t size, int page_prot) {
    int r;

    zz_size_t page_size;
    zz_addr_t aligned_addr;
    zz_size_t aligned_size;

    page_size    = zz_posix_vm_get_page_size();
    aligned_addr = (zz_addr_t)address & ~(page_size - 1);
    aligned_size = (1 + ((address + size - 1 - aligned_addr) / page_size)) * page_size;

    r = mprotect((zz_ptr_t)aligned_addr, aligned_size, page_prot);
    if (r == -1) {
        ZZ_ERROR_LOG("r = %d, at (%p) error!", r, (zz_ptr_t)address);
        return FALSE;
    }
    return TRUE;
}

bool zz_posix_vm_protect_as_executable(const zz_addr_t address, zz_size_t size) {
    return zz_posix_vm_protect(address, size, (PROT_READ | PROT_EXEC | PROT_WRITE));
}

bool zz_posxi_vm_protect_as_writable(const zz_addr_t address, zz_size_t size) {
    if (!zz_posix_vm_protect(address, size, (PROT_READ | PROT_EXEC | PROT_WRITE)))
        return FALSE;
    return TRUE;
}

//  void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
zz_ptr_t zz_posix_vm_allocate_pages(zz_size_t n_pages) {
    zz_ptr_t page_mmap;
    int kr;
    zz_size_t page_size;
    page_size = zz_posix_vm_get_page_size();

    if (n_pages <= 0) {
        n_pages = 1;
    }

    page_mmap = mmap(0, page_size * n_pages, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (page_mmap == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    if (!zz_posix_vm_protect((zz_addr_t)page_mmap, page_size * n_pages, (PROT_WRITE | PROT_READ)))
        return NULL;
    return (zz_ptr_t)page_mmap;
}

zz_ptr_t zz_posix_vm_allocate(zz_size_t size) {
    zz_size_t page_size;
    zz_ptr_t result;
    zz_size_t n_pages;

    page_size = zz_posix_vm_get_page_size();
    n_pages   = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

    result = zz_posix_vm_allocate_pages(n_pages);
    return (zz_ptr_t)result;
}

zz_ptr_t zz_posix_vm_allocate_near_pages(zz_addr_t address, zz_size_t range_size, zz_size_t n_pages) {
    zz_addr_t aligned_addr;
    zz_ptr_t page_mmap;
    zz_addr_t t;
    zz_size_t page_size;
    page_size = zz_posix_vm_get_page_size();

    if (n_pages <= 0) {
        n_pages = 1;
    }
    aligned_addr = (zz_addr_t)address & ~(page_size - 1);

    zz_addr_t target_start_addr = aligned_addr - range_size;
    zz_addr_t target_end_addr   = aligned_addr + range_size;

    for (t = target_start_addr; t < target_end_addr; t += page_size) {
        page_mmap = mmap((zz_ptr_t)t, page_size * n_pages, PROT_WRITE | PROT_READ,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (page_mmap != MAP_FAILED) {
            return (zz_ptr_t)page_mmap;
        }
    }
    return NULL;
}

zz_ptr_t zz_posix_vm_search_text_code_cave(zz_addr_t address, zz_size_t range_size, zz_size_t size) {
    char zeroArray[128];
    char readZeroArray[128];
    zz_addr_t aligned_addr, tmp_addr, target_search_start, target_search_end;
    zz_size_t page_size;

    memset(zeroArray, 0, 128);

    page_size           = zz_posix_vm_get_page_size();
    aligned_addr        = (zz_addr_t)address & ~(page_size - 1);
    target_search_start = aligned_addr - range_size;
    target_search_end   = aligned_addr + range_size;

    ZZ_DEBUG_LOG("searching for %p cave, use 0x1000 interval.", (zz_ptr_t)address);
    for (tmp_addr = target_search_start; tmp_addr < target_search_end; tmp_addr += 0x1000) {
        if (zz_posix_vm_check_address_valid_via_signal((zz_ptr_t)tmp_addr))
            if (memcpy(readZeroArray, (zz_ptr_t)tmp_addr, 128)) {
                if (!memcmp(readZeroArray, zeroArray, 128)) {
                    return (void *)tmp_addr;
                }
            }
    }
    return NULL;
}

/*
  ref:
  substitute/lib/darwin/execmem.c:execmem_foreign_write_with_pc_patch
  frida-gum-master/gum/gummemory.c:gum_memory_patch_code

  frida-gum-master/gum/backend-darwin/gummemory-darwin.c:gum_alloc_n_pages

  mach mmap use __vm_allocate and __vm_map
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/hurd/mmap.c
  https://github.com/bminor/glibc/blob/master/sysdeps/mach/munmap.c

  http://shakthimaan.com/downloads/hurd/A.Programmers.Guide.to.the.Mach.System.Calls.pdf
*/

bool zz_posix_vm_patch_code(const zz_addr_t address, const zz_ptr_t codedata, zz_size_t codedata_size) {
    zz_size_t page_size;
    zz_addr_t start_page_addr, end_page_addr;
    zz_size_t page_offset, range_size;

    page_size = zz_posix_vm_get_page_size();
    /*
      https://www.gnu.org/software/hurd/gnumach-doc/Memory-Attributes.html
     */
    start_page_addr = (address) & ~(page_size - 1);
    end_page_addr   = ((address + codedata_size - 1)) & ~(page_size - 1);
    page_offset     = address - start_page_addr;
    range_size      = (end_page_addr + page_size) - start_page_addr;

    //  another method, pelease read `REF`;

    // zz_ptr_t code_mmap = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
    //                           MAP_ANON | MAP_SHARED, -1, 0);
    // if (code_mmap == MAP_FAILED) {
    //   return;
    // }

    zz_ptr_t code_mmap = zz_posix_vm_allocate(range_size);

    memcpy(code_mmap, (void *)start_page_addr, range_size);

    memcpy(code_mmap + page_offset, codedata, codedata_size);

    /* SAME: mprotect(code_mmap, range_size, prot); */
    // if (!zz_posix_vm_protect((zz_addr_t)code_mmap, range_size, PROT_READ | PROT_EXEC))
    //     return FALSE;

    zz_addr_t target = (zz_addr_t)start_page_addr;
    zz_posxi_vm_protect_as_writable(start_page_addr, range_size);
    memcpy((zz_ptr_t)start_page_addr, (zz_ptr_t)code_mmap, range_size);
    zz_posix_vm_protect_as_executable(start_page_addr, range_size);
    munmap(code_mmap, range_size);
    return TRUE;
}
