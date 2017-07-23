#include "memory-utils.h"
#include <sys/mman.h>
#include <errno.h>

zint zz_query_page_size() { return getpagesize(); }

bool zz_read_task_memory(task_t t, zaddr addr, zpointer buf, zsize len) {
    vm_size_t dataCnt;
    dataCnt = 0;
    if (addr <= 0) {
        Serror("memory read address < 0");
        return false;
    }
    if (len <= 0) {
        Serror("memory read length <0");
        return false;
    }

    dataCnt = len;
    kern_return_t kr = vm_read_overwrite(t, addr, len, (zaddr) buf, (vm_size_t *) &dataCnt);

    if (kr)
        return false;
    if (len != dataCnt) {
        warnx("rt_read size return not match!");
        return false;
    }

    return true;
}

bool zz_check_address_valid_by_task(task_t t, zaddr addr) {
    if (addr <= 0)
        return false;
#define CHECK_LEN 1
    char n_read_bytes[1];
    unsigned int len;
    kern_return_t kr = vm_read_overwrite(t, addr, CHECK_LEN, (zaddr) & n_read_bytes, (vm_size_t *) &len);

    if (kr != KERN_SUCCESS || len != CHECK_LEN)
        return false;
    return true;
}

// http://renatocunha.com/blog/2015/12/msync-pointer-validity/
bool zz_check_address_valid_by_mem(void *p) {
    int ret = 0;
    size_t page_size;
    zpointer base;
    /* get the page size */
    page_size = zz_query_page_size();
    /* find the address of the page that contains p */
    base = (void *) ((((size_t) p) / page_size) * page_size);
    /* call msync, if it returns non-zero, return false */
    ret = msync(base, page_size, MS_ASYNC) != -1;
    return ret ? ret : errno != ENOMEM;
}


char *zz_read_task_string(task_t t, zaddr addr) {
    char x = '\0';
    zaddr end;
    char *str = NULL;

    //string upper limit 0x1000
    end = zz_memory_search_by_task(t, addr, addr + 0x1000, (zbyte * ) & x, 1);
    if (!end) {
        return NULL;
    }
    str = (char *) malloc(end - addr + 1);
    if (zz_read_task_memory(t, addr, str, end - addr + 1)) {
        return str;
    }

    return NULL;
}

char *zz_read_mem_string(zaddr addr) {
    char *xaddr = (char *) addr;
    unsigned int string_limit = 1024;
    unsigned int i;
    for (i = 0; i < string_limit; i++) {
        if (*(xaddr + i) == '\0')
            break;
    }
    if (i == string_limit)
        return NULL;
    else {
        char *result = (char *) malloc(i + 1);
        memcpy(result, xaddr, i + 1);
        return result;
    }
}

char *zz_read_fd_string(zaddr addr) {
    return zz_read_mem_string(addr);
}

task_t zz_get_pid_by_task(unsigned int pid) {
    task_t t;
    kern_return_t ret = task_for_pid(mach_task_self(), pid, &t);
    if (ret != KERN_SUCCESS) {
        printf("Attach to: %d Failed: %d %s\n", pid, ret, mach_error_string(ret));
        return 0;
    }
    return t;
}

//get dyld load address by task_info, TASK_DYLD_INFO
zaddr zz_get_dyld_load_address_by_task(task_t task) {
    //http://stackoverflow.com/questions/4309117/determining-programmatically-what-modules-are-loaded-in-another-process-os-x
    kern_return_t kr;
    task_flavor_t flavor = TASK_DYLD_INFO;
    task_dyld_info_data_t infoData;
    mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
    kr = task_info(task,
                   flavor,
                   (task_info_t) &infoData,
                   &task_info_outCnt);
    if (kr) {
        Serror("zz_get_dyld_load_address_by_task:task_info error");
        return 0;
    }
    struct dyld_all_image_infos *allImageInfos = (struct dyld_all_image_infos *) infoData.all_image_info_addr;
    allImageInfos = (struct dyld_all_image_infos *) malloc(sizeof(struct dyld_all_image_infos));
    if (zz_read_task_memory(task, infoData.all_image_info_addr, allImageInfos, sizeof(struct dyld_all_image_infos))) {
        return (zaddr)(allImageInfos->dyldImageLoadAddress);
    } else {
        Serror("zz_get_dyld_load_address_by_task:zz_read_task_memory error");
        return 0;
    }
}

zaddr zz_memory_search_by_task(task_t task, zaddr start, zaddr end, zbyte *data, zsize len) {
    if (start <= 0)
        Serror("memory search address < 0");
    if (start > end)
        Serror("memeory search end < start");
    zaddr addr = start;
    zbyte *buf = (zbyte *) malloc(len);
    while (end > addr) {
        if (zz_read_task_memory(task, addr, buf, len))
            if (!memcmp(buf, data, len)) {
                return addr;
            }
        addr += len;
    }
    return 0;
}
