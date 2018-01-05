/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "hookzz.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

void open_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    void *t = (void *)0x1234;
    STACK_SET(cs, "key_x", t, void *);
    STACK_SET(cs, "key_y", t, void *);
}

void open_post_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info)
{
    void *x = STACK_GET(cs, "key_x", void *);
    void *y = STACK_GET(cs, "key_y", void *);
}

__attribute__((constructor)) void test_hook_printf()
{
    void *open_ptr = (void *)open;

    ZzEnableDebugMode();
    ZzHookPrePost((void *)open_ptr, open_pre_call, open_post_call);

    open("/home/zz", O_RDONLY);
}

int main(int args, char **argv) {}
