#ifndef HOOKZZ_THREADSTACK_H_
#define HOOKZZ_THREADSTACK_H_

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

// (thead) CallStack
typedef struct _CallStack {
  std::vector<StackFrame *> stackframes;
} CallStack;

// ThreadSupport base on vm_core, support mutipl platforms.
class ThreadSupport {
public:
  static void PushStackFrame(StackFrame *stackframe) {
    CallStack *callstack = static_cast<CallStack *>(zz::Thread::GetThreadLocal(thread_callstack_key_));
    callstack->stackframes.push_back(stackframe);
  }

  static StackFrame *PopStackFrame() {
    CallStack *callstack   = static_cast<CallStack *>(zz::Thread::GetThreadLocal(thread_callstack_key_));
    StackFrame *stackframe = callstack->stackframes.back();
    callstack->stackframes.pop_back();
    return stackframe;
  }

  static void SetStackFrameContextValue(StackFrame *stackframe, char *key, void *value) {
    std::map<char *, void *> *kv_context = &stackframe->kv_context;
    kv_context->insert(std::pair<char *, void *>(key, value));
  };

  static void *GetStackFrameContextValue(StackFrame *stackframe, char *key) {
    std::map<char *, void *> kv_context = stackframe->kv_context;
    std::map<char *, void *>::iterator it;
    it = kv_context.find(key);
    if (it != kv_context.end()) {
      return (void *)it->second;
    }
    return NULL;
  };

  CallStack *CurrentThreadCallStack();

private:
  static zz::Thread::LocalStorageKey thread_callstack_key_;
};

#endif