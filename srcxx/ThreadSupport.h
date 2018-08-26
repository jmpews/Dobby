#ifndef ZZ_SRCXX_THREADSTACK_H_
#define ZZ_SRCXX_THREADSTACK_H_

#include <iostream>
#include <vector>
#include <map>

#include "srcxx/globals.h"

typedef struct _StackFrame {
  // context between `pre_call` and `post_call`
  std::map<char *, void *> kv_context;

  // origin function ret address
  void *orig_ret;
} StackFrame;

typedef struct _CallStack {
  std::vector<StackFrame *> stack_frames;
} CallStack;

#endif