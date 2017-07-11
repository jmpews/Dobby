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

int func(int x1, int x2, int x3, int x4)
{
    int y;
    y = x1+x2+x3+x4 + 1;
    return y;
}
int newfunc(int x1, int x2, int x3, int x4)
{
    int t = 0;
    printf("[*] hook success\n");
    t = oldfunc(1, 2, 3, 4);
    printf("[+] result from oldfunc: %d\n", t);
    return 0;
}

int main( int argc, const char* argv[]){

    // ZZInitialize();
    // ZZBuildHook((void *)func, (void *)newfunc, (void **)(&oldfunc));
    // ZZEnableHook((void *)func);
    while (1)
    {
        sleep(1);
        printf(".");
        fflush(stdout);
    }
}

