#include "hookzz.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

void open_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
    char *path = (char *)rs->general.regs.r0;
    printf("open file: %s\n", path);
}

void open_post_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {

    __attribute__((constructor)) void test_hook_printf() {
        void *open_ptr = (void *)open;

        ZzEnableDebugMode();
        // ZzHookPrePost((void *)open_ptr, open_pre_call, open_post_call);
        ZzHook((void *)open_ptr, NULL, NULL, open_pre_call, open_post_call, true);

        open("/home/zz", O_RDONLY);
    }
