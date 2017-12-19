//
// Created by jmpews on 2017/7/23.
//

#ifndef objcruntime_h
#define objcruntime_h

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../objc/oobjc.h"
#include "../zz.h"

/*
 * objc method
 */
struct _objc_method_info;

typedef std::vector<_objc_method_info *> objc_method_infos_t;

typedef struct _objc_class_info
{
  struct objc::objc_class *objc_class;
  zaddr class_vmaddr;
  zpointer class_fileoff;
  char *class_name;
  struct _objc_class_info *meta_class_info;
  struct _objc_class_info *super_class_info;
  objc_method_infos_t objc_method_infos;
} objc_class_info_t;

typedef std::vector<objc_class_info_t *> objc_class_infos_t;

/*
 * objc method
 */
typedef struct _objc_method_info
{
  struct objc::method_t *objc_method;
  zaddr method_vmaddr;
  zpointer method_fileoff;
  char *method_name;
  objc_class_info_t *objc_class_info;
} objc_method_info_t;

typedef std::unordered_map<zaddr, objc_method_info_t *> objc_method_infos_map_t;
typedef std::unordered_map<std::string, objc_method_info_t *>
    objc_method_infos_strmap_t;

#define CLASS_FUNC 2
#define DEFAULT_FUNC 1

typedef struct
{
  zaddr func_vmaddr;
  zpointer method_vmaddr;
  int func_type;
  objc_method_info_t *class_method;
} func_info_t;

typedef std::vector<func_info_t *> funcs_t;

class ZzObjcRuntime
{
public:
  objc_class_infos_t objc_class_infos;
  objc_method_infos_t objc_method_infos;
  objc_method_infos_map_t objc_method_infos_map;
  objc_method_infos_strmap_t objc_method_infos_strmap;
  funcs_t funcs;
};

#endif // MACHOPARSER_OBJCRUNTIME_H
