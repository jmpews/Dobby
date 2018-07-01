#include "memory-helper-posix.h"
#include "core.h"
#include "hookzz.h"
#include "memory_manager.h"

extern void __clear_cache(void *beg, void *end);

void posix_memory_helper_cclass(set_page_permission)(void *page_address, int prot, int n) {
    int page_size = posix_memory_helper_cclass(get_page_size)();
    int r;
    r = mprotect((zz_ptr_t)page_address, page_size * n, prot);
    if (r == -1) {
        ERROR_LOG("r = %d, at (%p) error!", r, (zz_ptr_t)page_address);
        return;
    }
    return;
}

int posix_memory_helper_cclass(get_page_size)() {
    int page_size = sysconf(_SC_PAGESIZE);
    return page_size;
}

void *posix_memory_helper_cclass(allocate_page)(int prot, int n) {
    int page_size = posix_memory_helper_cclass(get_page_size)();

    void *mmap_page = mmap(0, 1, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    mprotect(mmap_page, (size_t)page_size, (PROT_READ | PROT_WRITE));
    return mmap_page;
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

void posix_memory_helper_cclass(patch_code)(void *dest, void *src, int count) {
    void *dest_page = NULL;
    int offset      = 0;

    int page_size = posix_memory_helper_cclass(get_page_size)();

    // https://www.gnu.org/software/hurd/gnumach-doc/Memory-Attributes.html
    dest_page = (void *)((zz_addr_t)dest & ~(page_size - 1));
    offset    = (zz_addr_t)dest - (zz_addr_t)dest_page;

    // another method, pelease read `REF`;
    // zz_ptr_t code_mmap = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
    //                           MAP_ANON | MAP_SHARED, -1, 0);
    // if (code_mmap == MAP_FAILED) {
    //   return;
    // }

    void *copy_page = posix_memory_helper_cclass(allocate_page)(PROT_R_X, 1);

    memcpy(copy_page, (void *)dest_page, page_size);
    memcpy((void *)((zz_addr_t)copy_page + offset), src, count);

    /* SAME: mprotect(code_mmap, range_size, prot); */
    posix_memory_helper_cclass(set_page_permission)(copy_page, PROT_WRITE | PROT_READ, 1);
    memcpy(dest_page, copy_page, page_size);
    posix_memory_helper_cclass(set_page_permission)(copy_page, PROT_EXEC | PROT_READ, 1);
    __clear_cache((void *)dest, (void *)((uintptr_t)dest + count));

    // TODO
    munmap(copy_page, page_size);
    return;
}
