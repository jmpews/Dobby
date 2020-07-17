#include "./dobby_objective_c.h"

#include <stdio.h>

#include <objc/runtime.h>

extern "C" {
#include "helpers/variable_cache.h"
}

/* clang -rewrite-objc main.m */

static int auto_return_constant(id obj, SEL sel) {
  Class class_           = object_getClass(obj);
  const char *class_name = class_getName(class_);
  const char *sel_name   = sel_getName(sel);

  char key[128] = {0};
  sprintf(key, "%s__%s", class_name, sel_name);
  return cache(key);
}

void DobbyOCReturnConstant(const char *class_name, const char *selector_name, int value) {
  Class class_ = objc_getClass(class_name);
  SEL sel_     = sel_registerName(selector_name);

  char key[128] = {0};
  sprintf(key, "%s__%s", class_name, selector_name);
  stash(key, value);

  Method method_ = class_getInstanceMethod(class_, sel_);
  if (!method_)
    method_ = class_getClassMethod(class_, sel_);

  if (!method_) {
    printf("not found class: %s, selector: %s method\n", class_name, selector_name);
    return;
  }

  method_setImplementation(method_, (IMP)auto_return_constant);
}
