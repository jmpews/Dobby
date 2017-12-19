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

#include "MachoTools.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "zzdeps/common/LEB128.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/darwin/memory-utils-darwin.h"
#ifdef __cplusplus
}
#endif

#include "parsers/ObjcRuntime.h"

#include "zz.h"

void PrintClassInfo(objc_class_info_t *objc_class_info)
{
    if (!objc_class_info)
        return;

    Xinfo("Class Name: %s, Address: %p", objc_class_info->class_name,
          (zpointer)objc_class_info->class_vmaddr);

    objc_method_infos_t *objc_method_infos;
    objc_method_infos = &(objc_class_info->objc_method_infos);
    std::vector<objc_method_info_t *>::iterator iter;
    objc_method_info_t *objc_method_info;
    for (iter = objc_method_infos->begin(); iter != objc_method_infos->end();
         iter++)
    {
        objc_method_info = (*iter);
        Xinfo("- %s, %p", objc_method_info->method_name,
              (zpointer)objc_method_info->method_vmaddr);
    }
}
