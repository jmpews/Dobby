//
// Created by jmpews on 2017/7/23.
//

#include <mach/mach_types.h>

#include <iostream>
#include <vector>

#include "zz.h"
#include "MachoRuntime.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "../zzdeps/common/debugbreak.h"
#ifdef __cplusplus
}
#endif

// TODO: belong to Macho class ???
zaddr MachoRuntime::oobject_getClass(zaddr object_addr)
{
    /*
        fuck the MASK, take lost of my time, pease ref:
        1.`objc-709/objc-msg-arm64.s`
        2. objc-709/runtime/objc-object.h:161 `(Class)(isa.bits & ISA_MASK)`
        3. objc-709/runtime/objc-object.h:77 `objc_object::getIsa()`
     */
    struct objc::objc_object tp_objc_object;
    zaddr class_addr = 0;

#if defined(__arm64__)
    if (object_addr <= 0 || objc::_objc_isTaggedPointer((zpointer)object_addr))
    {
        return 0;
    }
    macho_read(object_addr, &tp_objc_object, sizeof(struct objc::objc_object));
    class_addr = reinterpret_cast<zaddr>(tp_objc_object.isa.bits) & 0x0000000ffffffff8;
#elif defined(__x86_64__)
    // ref: objc4-709/runtime/Messengers.subproj/objc-msg-x86_64.s `.macro GetIsaFast`
    if (object_addr)
    {
        if (!(object_addr & 0x1))
        {
            macho_read(object_addr, &class_addr, sizeof(class_addr));
            class_addr = class_addr & 0x00007ffffffffff8;
        }
    }
#endif
    return class_addr;
}

/*
 * `tp` is equal to `temp`
 */
bool MachoRuntime::oobject_isClass(zaddr object_addr)
{
    zaddr class_addr;
    struct objc::objc_class tp_objc_class;
    zaddr objc_class_data_addr;

    if (objc::_objc_isTaggedPointer((zpointer)object_addr))
        return FALSE;

    class_addr = oobject_getClass(object_addr);
    macho_runtime_read(class_addr, &tp_objc_class, sizeof(struct objc::objc_class));

    objc_class_data_addr = (zaddr)objc::data(tp_objc_class.bits);

    struct objc::class_ro_t objc_data_ro;
    struct objc::class_rw_t objc_data_rw;

    /*
     *  check if realizeClass(), another word RW_REALIZED|RW_REALIZING
     *  objc-runtime/runtime/objc-runtime-new.mm: realizeClass
     *  check realizeClass()
     */

    uint32_t flags;
    macho_runtime_read(objc_class_data_addr, &flags, sizeof(uint32_t));
    if (flags & (RW_REALIZED | RW_REALIZING))
    {
        macho_runtime_read(objc_class_data_addr, &objc_data_rw, sizeof(struct objc::class_rw_t));
        macho_runtime_read((zaddr)(objc_data_rw.ro), &objc_data_ro, sizeof(struct objc::class_ro_t));
        return (objc_data_ro.flags) & 0x1;
    }
    else
    {
        // debug_break();
        return TRUE;
    }
}

objc_class_info_t *MachoRuntime::parse_OBJECT(zaddr objc_addr)
{
    objc_class_info_t *objc_class_info;
    zaddr class_addr;

    if (!objc_addr)
        return NULL;

    class_addr = this->oobject_getClass(objc_addr);

    if (this->input.type == MEM_INPUT)
        if (this->oobject_isClass(objc_addr))
        {
            class_addr = objc_addr;
        }

    // cache!!!
    objc_class_info = search_class_addr(&this->objcruntime.objc_class_infos, class_addr);

    // if parse at first, no need this.
    if (NULL == objc_class_info)
    {
        debug_break();
        // just parse the class which the address in the self process memory range, not all. (if all, the logfile will so big)
        objc_class_info = new objc_class_info_t();
        objc_class_info->class_vmaddr = class_addr;
        parse_CLASS(objc_class_info);
    }
    return objc_class_info;
}

/*
 * search method by method name in method's vecotr.
 */

objc_method_info_t *search_method_name(objc_method_infos_t *objc_method_infos, char *method_name)
{
    std::vector<objc_method_info_t *>::iterator iter;
    objc_method_info_t *objc_method_info;
    for (iter = objc_method_infos->begin(); iter != objc_method_infos->end(); iter++)
    {
        objc_method_info = (*iter);
        if (!strcmp(objc_method_info->method_name, method_name))
        {
            Sdebug("hit cache :)");
            return objc_method_info;
        }
    }
    return NULL;
}

/*
 * search method by method address in method's vecotr.
 */
objc_method_info_t *search_method_addr(objc_method_infos_t *objc_method_infos, zaddr method_addr)
{
    /*
        use vector to search so slow.
    */
    std::vector<objc_method_info_t *>::iterator iter;
    objc_method_info_t *objc_method_info;
    for (iter = objc_method_infos->begin(); iter != objc_method_infos->end(); iter++)
    {
        objc_method_info = (*iter);
        if (objc_method_info->method_vmaddr == method_addr)
        {
            Sdebug("hit cache :)");
            return objc_method_info;
        }
    }
    return NULL;
}

/*
 * search class by class address.
 */

objc_class_info_t *search_class_addr(objc_class_infos_t *objc_class_infos, zaddr addr)
{
    std::vector<objc_class_info_t *>::iterator iter;
    objc_class_info_t *xobjc_class_info;
    for (iter = objc_class_infos->begin(); iter != objc_class_infos->end(); iter++)
    {
        xobjc_class_info = *iter;

        if (xobjc_class_info->class_vmaddr == addr)
        {
            return xobjc_class_info;
        }
    }
    return NULL;
}

/*
    hash search method by method address in method's hash-map.
*/

objc_method_info_t *hash_search_method_addr(objc_method_infos_map_t *objc_method_infos_map, zaddr method_addr)
{

    std::unordered_map<zaddr, objc_method_info_t *>::iterator it;
    if ((it = objc_method_infos_map->find(method_addr)) != objc_method_infos_map->end())
    {
        return it->second;
    }
    else
    {
        return NULL;
    }
    return NULL;
}

/*
    hash search method by method name in method's hash-map.
*/

objc_method_info_t *hash_search_method_name(objc_method_infos_strmap_t *objc_method_infos_strmap, char *method_name)
{

    std::unordered_map<std::string, objc_method_info_t *>::iterator it;
    if ((it = objc_method_infos_strmap->find(std::string((char *)method_name))) != objc_method_infos_strmap->end())
    {
        return it->second;
    }
    else
    {
        return NULL;
    }
    return NULL;
}
