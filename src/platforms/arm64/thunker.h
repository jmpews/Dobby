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


#include "../../zzdeps/zz.h"
#include "../../../include/hookzz.h"
#include "writer.h"

#include "../../interceptor.h"

void zz_build_enter_thunk(ZZWriter *writer);

void zz_build_leave_thunk(ZZWriter *writer);

void thunker_build_enter_trapoline(ZZWriter *writer, zpointer entry_ptr, zpointer enter_thunk_ptr);

void thunker_build_leave_trapoline(ZZWriter *writer, zpointer entry_ptr, zpointer enter_thunk_ptr);
