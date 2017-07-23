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

#include <objc/message.h>
#include "../include/hookzz.h"
#include <stdio.h>

__attribute__((constructor)) void hook_objc_msgSend() {
    ZZInitialize();
    ZZBuildHook((void *) objc_msgSend, (void *) objc_msgSend, NULL, NULL, NULL);
    ZZEnableHook((void *) objc_msgSend);
}

int main(int argc, const char *argv[]) {
    printf("hello world.\n");
}