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

#ifndef zzdeps_darwin_macho_utils_h
#define zzdeps_darwin_macho_utils_h

#include <stdio.h>
#include <stdlib.h>
#include <err.h>


#include <mach/task.h>

#include "../zz.h"

zpointer zz_get_dyld_load_address_via_task(task_t task);
task_t zz_get_pid_via_task(int pid);

#endif
