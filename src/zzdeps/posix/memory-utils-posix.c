
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
// for : getpagesize,
#include <unistd.h>

#include "memory-utils-posix.h"
// http://renatocunha.com/blog/2015/12/msync-pointer-validity/
bool zz_vm_check_address_valid_via_msync(const zpointer p)
{
    int ret = 0;
    zsize page_size;
    zpointer base;
    /* get the page size */
    page_size = zz_vm_get_page_size();
    /* find the address of the page that contains p */
    base = (void *)((((size_t)p) / page_size) * page_size);
    /* call msync, if it returns non-zero, return false */
    ret = msync(base, page_size, MS_ASYNC) != -1;
    return ret ? ret : errno != ENOMEM;
}

// ATTENTION !!!
// lldb is still catch EXC_BAD_ACCESS, without lldb is ok.
// https://www.cocoawithlove.com/2010/10/testing-if-arbitrary-pointer-is-valid.html
// https://stackoverflow.com/questions/26829119/how-to-make-lldb-ignore-exc-bad-access-exception
// ---check start---
#include <signal.h>
#include <setjmp.h>

static sigjmp_buf sigjmp_env;

void PointerReadFailedHandler(int signum)
{
    siglongjmp(sigjmp_env, 1);
}

bool zz_vm_check_address_valid_via_signal(zpointer p)
{
    // Set up SIGSEGV and SIGBUS handlers
    struct sigaction new_segv_action, old_segv_action;
    struct sigaction new_bus_action, old_bus_action;
    new_segv_action.sa_handler = PointerReadFailedHandler;
    new_bus_action.sa_handler = PointerReadFailedHandler;
    sigemptyset(&new_segv_action.sa_mask);
    sigemptyset(&new_bus_action.sa_mask);
    new_segv_action.sa_flags = 0;
    new_bus_action.sa_flags = 0;
    sigaction(SIGSEGV, &new_segv_action, &old_segv_action);
    sigaction(SIGBUS, &new_bus_action, &old_bus_action);

    // The signal handler will return us to here if a signal is raised
    if (sigsetjmp(sigjmp_env, 1))
    {
        sigaction(SIGSEGV, &old_segv_action, NULL);
        sigaction(SIGBUS, &old_bus_action, NULL);
        return false;
    }
    // ATTENTION !!! this function is conflict with LLDB, reason is below.
    // lldb is still catch EXC_BAD_ACCESS, without lldb is ok.
    // or you can use `zz_check_address_valid_via_mem` replace
    // https://stackoverflow.com/questions/26829119/how-to-make-lldb-ignore-exc-bad-access-exception
    char x = *(char *)p;
    return true;
}

zsize zz_vm_get_page_size() { return getpagesize(); }
