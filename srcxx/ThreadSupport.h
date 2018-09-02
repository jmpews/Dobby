#ifndef ZZ_SRCXX_THREADSTACK_H_
#define ZZ_SRCXX_THREADSTACK_H_

#include <iostream>
#include <map>
#include <vector>

#include "srcxx/globals.h"

#include "vm_core/platform/platform.h"

typedef struct _StackFrame {
  // context between `pre_call` and `post_call`
  std::map<char *, void *> kv_context;

  // origin function ret address
  void *orig_ret;
} StackFrame;

typedef struct _CallStack {
  std::vector<StackFrame *> stackframes;
} CallStack;

// ThreadSupport base on vm_core, support mutipl platforms.
class ThreadSupport {
public:
  static void PushStackFrame(StackFrame *stackframe);

  static StackFrame *PopStackFrame();

  static void *GetStackFrameContextValue(StackFrame *stackframe, const char *key);

  static void SetStackFrameContextValue(StackFrame *stackframe, const char *key, const void *value);

  CallStack *CurrentThreadCallStack();

private:
  static zz::base::Thread::LocalStorageKey thread_callstack_key_;
};

#endif