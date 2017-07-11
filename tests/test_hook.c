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

#include <stdio.h>
#include <unistd.h>

#include "../include/hookzz.h"

int (*oldfunc)(int, int, int, int);

extern int func(int x1, int x2, int x3, int x4);
int newfunc(int x1, int x2, int x3, int x4)
{
    int t = 0;
    printf("[*] hook success\n");
    t = oldfunc(1, 2, 3, 4);
    printf("[+] result from oldfunc: %d\n", t);
    return 0;
}

// #include <mach-o/dyld.h>
// #include <mach/mach_init.h>

// #include <mach/vm_statistics.h>
// #include <sys/mman.h>
// #include <assert.h>
// #include <string.h>
// #include <unistd.h>
// #include <mach/error.h>
// #include "/Users/jmpews/Downloads/evilHOOK.bak/InlineHook/deps/darwin/mach_vm.h"

__attribute__((constructor)) void test_hook()
{
    ZZInitialize();
    ZZBuildHook((void *)func, (void *)newfunc, (void **)(&oldfunc));
    ZZEnableHook((void *)func);
}

// int main( int argc, const char* argv[]){
//     int t = 0;
//     ZZInitialize();
//     ZZBuildHook((void *)func, (void *)newfunc, (void **)(&oldfunc));
//     ZZEnableHook((void *)func);
//     t = func(1, 2, 3, 4);
//     printf("[+] result from newfunc: %d\n", t);

//     while (1)
//     {
//         sleep(1);
//         printf(".");
//         fflush(stdout);
//     }
// }

