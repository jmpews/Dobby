//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef zzdeps_darwin_utils_h
#define zzdeps_darwin_utils_h

#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include <mach/task_info.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include "zz.h"

//#ifdef __arm64__
//#else
//#include <mach/mach_vm.h>
//#endif

zint zz_query_page_size();
task_t zz_get_pid_by_task(unsigned int pid);

bool zz_read_task_memory(task_t t, zaddr addr, zpointer buf, zsize len);

char *zz_read_task_string(task_t t, zaddr addr);

char *zz_read_fd_string(zaddr addr);

char *zz_read_mem_string(zaddr addr);

zaddr zz_memory_search_by_task(task_t task, zaddr start, zaddr end, zbyte *data, zsize len);


bool zz_check_address_valid_by_task(task_t t, zaddr addr);
bool zz_check_address_valid_by_signal(void *p);

bool zz_check_address_valid_by_mem(void *p);

zaddr zz_get_dyld_load_address_by_task(task_t task);

#endif
