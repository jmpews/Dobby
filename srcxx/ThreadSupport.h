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
  std::vector<StackFrame *> stack_frames;
} CallStack;

// ThreadSupport base on vm_core, support mutipl platforms.
class ThreadSupport {
public:
  static void PushStackFrame(StackFrame *stack_frame) {
    CallStack *call_stack = static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_call_stack_key_));
    call_stack->stack_frames.push_back(stack_frame);
  };

  static StackFrame *PushStackFrame() {
    CallStack *call_stack = static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_call_stack_key_));
    return static_cast<StackFrame *>(call_stack->stack_frames.pop_back());
  };

  static CallStack *CurrentThreadCallStack();

  static void SetStackFrameContextValue(StackFrame *stack_frame, const char *key, void *value) {
    std::map<char *, void *> kv_context = stack_frame->kv_context;
    kv_context.insert(std::pair<char *, void *>(key, value));
  };

  static void *GetStackFrameContextValue(StackFrame *stack_frame, const char *key) {
    std::map<char *, void *> kv_context = stack_frame->kv_context;
    std::map<char *, void *>::iterator it;
    it = kv_context.find(key);
    if (it != kv_context.end()) {
      return (void *)it->second;
    }
    return NULL;
  };

private:
  static zz::base::Thread::LocalStorageKey thread_call_stack_key_;
};

#endif