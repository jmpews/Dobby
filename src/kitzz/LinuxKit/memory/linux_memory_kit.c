#include "LinuxKit/memory/linux_memory_kit.h"
#include "CommonKit/memory/common_memory_kit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


MemoryLayout *zz_linux_vm_get_memory_layout_via_pid(pid_t pid) {
    char filename[64];
    char buf[256];
    FILE *fp;
    MemoryLayout *mlayout;

    mlayout = (MemoryLayout *)malloc(sizeof(MemoryLayout));
    memset(mlayout, 0, sizeof(MemoryLayout));

    // given pid, open /proc/pid/maps; or not, open current maps.
    if (pid > 0) {
        sprintf(filename, "/proc/%d/maps", pid);
    } else {
        sprintf(filename, "/proc/self/maps");
    }

    fp = fopen(filename, "r");
    if (fp < 0) {
        return NULL;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        zz_addr_t start, end;
        unsigned dev, sdev;
        unsigned long inode;
        unsigned long long offset;
        char prot[5];
        char path[64];
        int len;

        /* format in /proc/pid/maps is constructed as below in fs/proc/task_mmu.c
        167	seq_printf(m,
        168			   "%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu ",
        169			   vma->vm_start,
        170			   vma->vm_end,
        171			   flags & VM_READ ? 'r' : '-',
        172			   flags & VM_WRITE ? 'w' : '-',
        173			   flags & VM_EXEC ? 'x' : '-',
        174			   flags & VM_MAYSHARE ? flags & VM_SHARED ? 'S' : 's' : 'p',
        175			   pgoff,
        176			   MAJOR(dev), MINOR(dev), ino);
        177
        178		if (file) {
        179			seq_pad(m, ' ');
        180			seq_file_path(m, file, "");
        181		} else if (mm && is_stack(priv, vma)) {
        182			seq_pad(m, ' ');
        183			seq_printf(m, "[stack]");
        184		}
         */
        if (sscanf(buf, "%lx-%lx %s %llx %x:%x %lu %s", &start, &end, prot, &offset, &dev, &sdev, &inode, path) != 8)
            continue;
        mlayout->mem[mlayout->size].start = (zz_ptr_t)start;
        mlayout->mem[mlayout->size].end   = (zz_ptr_t)end;
        mlayout->mem[mlayout->size++].flags =
            (prot[0] == 'r' ? (1 << 0) : 0) | (prot[1] == 'w' ? (1 << 1) : 0) | (prot[2] == 'x' ? (1 << 2) : 0);
    }
    return mlayout;
}

zz_ptr_t zz_linux_vm_search_code_cave(zz_addr_t address, zz_size_t range_size, zz_size_t size) {
    char zeroArray[128];
    char readZeroArray[128];
    zz_addr_t aligned_addr, tmp_addr, search_start, search_end, search_start_limit, search_end_limit;
    zz_size_t page_size;

    zz_ptr_t result_ptr;
    memset(zeroArray, 0, 128);

    search_start_limit = address - range_size;
    search_end_limit   = address + range_size;

    MemoryLayout *mlayout = zz_linux_vm_get_memory_layout_via_pid(-1);

    int i;
    for (i = 0; i < mlayout->size; i++) {
        if (mlayout->mem[i].flags == (1 << 0 | 1 << 2)) {
            search_start = (zz_addr_t)mlayout->mem[i].start;
            search_end   = (zz_addr_t)mlayout->mem[i].end;

            if (search_start < search_start_limit) {

                if (search_end > search_start_limit && search_end < search_end_limit) {
                    search_start = search_start_limit;
                } else if (search_end > search_end_limit) {
                    search_start = search_start_limit;
                    search_end   = search_end_limit;
                } else {
                    continue;
                }
            } else if (search_start >= search_start_limit && search_start <= search_end_limit) {
                if (search_end > search_start_limit && search_end < search_end_limit) {
                } else if (search_end > search_end_limit) {
                    search_end = search_end_limit;
                } else {
                    continue;
                }
            } else {
                continue;
            }

            result_ptr = zz_vm_search_data((zz_ptr_t)search_start, (zz_ptr_t)search_end, (char *)zeroArray, size);
            if (result_ptr) {
                free(mlayout);
                return result_ptr;
            }
        }
    }
    free(mlayout);
    return NULL;
}
