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

#include <mach/mach_types.h>

#include <iostream>
#include <vector>
#include <mach-o/loader.h>

#include <assert.h>

#include "zz.h"
#include "Macho.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "../zzdeps/common/LEB128.h"
#ifdef __cplusplus
}
#endif

bool Macho::parse_SECT()
{
    char *segname;
    char *sectname;
    segment_command_64_info_t text_seg;
    segment_command_64_info_t data_seg;

    for (const auto &tp_seg_cmd_info : this->loadcommands.segment_command_64_infos)
    {
        segname = tp_seg_cmd_info.seg_cmd_64->segname;
        if (!strcmp(segname, "__TEXT"))
        {
            text_seg = tp_seg_cmd_info;
        }
        if (!strcmp(segname, "__DATA"))
        {
            data_seg = tp_seg_cmd_info;
        }
    }

    for (const auto &sect : data_seg.sect_64_infos)
    {
        sectname = sect.sect_64->sectname;
        /* iterate dump section */
        if (!strcmp(sect.sect_64->sectname, "__objc_classlist__DATA"))
        {
            parse_SECT_CLASSLIST(&sect);
        }
    }
    return TRUE;
}

const section_64_info_t *Macho::get_sect_by_name(char *sectname)
{
    for (const auto &sect : this->loadcommands.section_infos)
    {
        /* iterate dump section */
        if (!strcmp(sect.sect_64->sectname, sectname))
        {
            return &sect;
        }
    }
    return NULL;
}

bool Macho::parse_SECT_CLASSLIST(const section_64_info_t *sect_info)
{
    Sdebug("start dump SECT_CLASSLIST...");

    zaddr classlist_addr, class_addr;
    objc_class_info_t *objc_class_info;
    zsize classlist_count;
    struct section_64 *sect;
    sect = sect_info->sect_64;

    // __objc_classlist__DATA section addr

    classlist_addr = macho_runtime_address(sect_info->offset);

    classlist_count = (sect->size) / sizeof(zaddr);

    for (zsize i = 0; i < classlist_count; ++i)
    {
        // get class address, start dump class
        macho_read(classlist_addr + i * sizeof(zpointer), &class_addr, sizeof(zpointer));
        objc_class_info = new objc_class_info_t();

        objc_class_info->class_vmaddr = class_addr;

        parse_CLASS(objc_class_info);
        //        parse_META_CLASS(objc_class_info);
        //        parse_SUPER_CLASS(objc_class_info);

        this->objcruntime.objc_class_infos.push_back(objc_class_info);
    }
    return TRUE;
}

/* parse meta class */
bool Macho::parse_META_CLASS(objc_class_info_t *objc_class_info)
{
    zaddr meta_class_addr = (zaddr)objc_class_info->objc_class->isa;

    objc_class_info_t *meta_objc_class_info = new objc_class_info_t();
    meta_objc_class_info->class_vmaddr = meta_class_addr;

    objc_class_info->meta_class_info = meta_objc_class_info;
    parse_CLASS(meta_objc_class_info);
    return TRUE;
}

/* parse super class */
bool Macho::parse_SUPER_CLASS(objc_class_info_t *objc_class_info)
{
    zaddr super_class_addr = (zaddr)objc_class_info->objc_class->superclass;

    objc_class_info_t *meta_objc_class_info = new objc_class_info_t();
    meta_objc_class_info->class_vmaddr = super_class_addr;

    objc_class_info->super_class_info = meta_objc_class_info;
    parse_CLASS(meta_objc_class_info);
    return TRUE;
}

/* parse class */
bool Macho::parse_CLASS(objc_class_info_t *objc_class_info)
{
    zaddr class_addr;
    class_addr = objc_class_info->class_vmaddr;

#define CLASS_PARSE_ALL 1
#define CLASS_PARSE_SIMPLE 2

    int class_parse_flag = CLASS_PARSE_ALL;

    /*
     * another choice use namespace
     * using namespace objc;
     */

    struct objc::objc_class *objc_class;
    objc_class = (struct objc::objc_class *)malloc(sizeof(struct objc::objc_class));
    objc_class_info->objc_class = objc_class;

    macho_runtime_read(class_addr, objc_class, sizeof(struct objc::objc_class));

    zaddr objc_class_data_addr = (zaddr)objc::data(objc_class->bits);

    /*
     *  check if realizeClass(), another word RW_REALIZED|RW_REALIZING
     *  objc-runtime/runtime/objc-runtime-new.mm: realizeClass
     *  check realizeClass()
     */
    uint32_t flags;
    struct objc::class_rw_t objc_data_rw;
    char *class_name;
    macho_runtime_read(objc_class_data_addr, &flags, sizeof(uint32_t));
    struct objc::class_ro_t objc_data_ro;
    if (flags & (RW_REALIZED | RW_REALIZING))
    {
        Sdebug("class has been realized");
        macho_runtime_read(objc_class_data_addr, &objc_data_rw, sizeof(struct objc::class_rw_t));
        macho_runtime_read((zaddr)(objc_data_rw.ro), &objc_data_ro, sizeof(struct objc::class_ro_t));
    }
    else
    {
        Sdebug("class not be realized");
        macho_runtime_read(objc_class_data_addr, &objc_data_ro, sizeof(struct objc::class_ro_t));
    }

    /* start dump class name */
    class_name = macho_runtime_read_string((zaddr)(objc_data_ro.name));
    if (class_name)
    {
        Xdebug("dumping class \'%s\', %p", class_name, (zpointer)(objc_data_ro.name));
    }
    else
    {
        Xdebug("dumping class %p name faild, may be not be used", (zpointer)objc_class_info->class_vmaddr);
    }

    objc_class_info->class_name = class_name;

    /* start dump methods */
    objc::method_list_t objc_methods;
    zaddr methodlist_addr;
    objc::method_t objc_method;
    char *method_name;
    if (class_parse_flag == CLASS_PARSE_ALL && objc_data_ro.baseMethodList)
    {
        macho_runtime_read((zaddr)(objc_data_ro.baseMethodList), &objc_methods, sizeof(objc::method_list_t));

        //objc4-706/objc-runtime-new.h:92, please read about 'entsize_list_tt'
        methodlist_addr = (zaddr)(objc_data_ro.baseMethodList) + sizeof(uint32_t) * 2;
        for (int i = 0; i < objc_methods.count; ++i)
        {
            zaddr method_addr = methodlist_addr + i * sizeof(objc::method_t);
            macho_runtime_read(method_addr, &objc_method, sizeof(objc::method_t));
            method_name = macho_runtime_read_string((zaddr)(objc_method.name));

            objc_method_info_t *objc_method_info = new objc_method_info_t();
            objc_method_info->method_vmaddr = (zaddr)objc_method.imp;
            objc_method_info->method_name = method_name;
            objc_method_info->objc_class_info = objc_class_info;

            objc_class_info->objc_method_infos.push_back(objc_method_info);
            this->objcruntime.objc_method_infos.push_back(objc_method_info);
            this->objcruntime.objc_method_infos_map.insert(std::make_pair((zaddr)objc_method.imp, objc_method_info));
            this->objcruntime.objc_method_infos_strmap.insert(std::make_pair(std::string((char *)(objc_method_info->method_name)), objc_method_info));

            Xdebug("\tmethod name \'%s\'", method_name);
            // free(method_name);
        }
    }
    else
    {
        Xdebug("%s no methods.", class_name);
    }

    /* start dump ivars */
    objc::ivar_list_t objc_ivars;
    zaddr ivarlist_addr;
    objc::ivar_t tmp_ivar;
    char *ivar_name;
    if (class_parse_flag == CLASS_PARSE_ALL && objc_data_ro.ivars)
    {
        macho_runtime_read((zaddr)(objc_data_ro.ivars), &objc_ivars, sizeof(objc::ivar_list_t));
        ivarlist_addr = (zaddr)(objc_data_ro.ivars) + sizeof(uint32_t) * 2;

        for (int i = 0; i < objc_ivars.count; ++i)
        {
            macho_runtime_read(ivarlist_addr + i * sizeof(objc::ivar_t), &tmp_ivar, sizeof(objc::ivar_t));
            ivar_name = macho_runtime_read_string((zaddr)(tmp_ivar.name));
            Xdebug("\t ivar name \'%s\'", ivar_name);
            free(ivar_name);
        }
    }
    else
    {
        Xdebug("%s no ivars.", class_name);
    }

    return TRUE;
}
