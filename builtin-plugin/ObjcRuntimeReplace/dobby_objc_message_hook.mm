#include "dobby_objc_message_hook.h"

#include <stdio.h>
#include <objc/runtime.h>

/* clang -rewrite-objc main.m */

void DobbyHookMessageEx(const char *class_name, const char *selector_name, void *fake_impl, void **out_orig_impl) {
  Class class_ = objc_getClass(class_name);
  SEL sel_ = sel_registerName(selector_name);

  Method method_ = class_getInstanceMethod(class_, sel_);
  if (!method_) {
    method_ = class_getClassMethod(class_, sel_);
    if (!method_) {
      // ERROR_LOG("Not found class: %s, selector: %s method\n", class_name, selector_name);
      return;
    }
  }

  auto orig_impl = (void *)method_setImplementation(method_, (IMP)fake_impl);
  if (out_orig_impl) {
    *out_orig_impl = orig_impl;
  }
}

void *DobbyMessageMethodResolver(const char *class_name, const char *selector_name) {
  Class class_ = objc_getClass(class_name);
  SEL sel_ = sel_registerName(selector_name);

  Method method_ = class_getInstanceMethod(class_, sel_);
  if (!method_)
    method_ = class_getClassMethod(class_, sel_);

  if (!method_) {
    // DEBUG_LOG("Not found class: %s, selector: %s method\n", class_name, selector_name);
    return nullptr;
  }
  return (void *)method_getImplementation(method_);
}
