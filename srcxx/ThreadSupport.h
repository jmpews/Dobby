#ifndef ZZ_SRCXX_THREADSTACK_H_
#define ZZ_SRCXX_THREADSTACK_H_

#include <iostream>
#include <vector>
#include <map>

#include "srcxx/globals.h"

#include "srcxx/base_core/platform/platform.h"

typedef struct _StackFrame {
  // context between `pre_call` and `post_call`
  std::map<char *, void *> kv_context;

  // origin function ret address
  void *orig_ret;
} StackFrame;

typedef struct _CallStack {
  std::vector<StackFrame *> stack_frames;
} CallStack;

// ThreadSupport base on base_core, support mutipl platforms.
class ThreadSupport {
public:
  void PushStackFrame(StackFrame *stack_frame) {
    CallStack *call_stack = static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_call_stack_key_));
    call_stack->stack_frames.push_back(stack_frame);
  };

  StackFrame *PushStackFrame() {
    CallStack *call_stack = static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_call_stack_key_));
    return call_stack->stack_frames.pop_back()
  };

  CallStack *CurrentThreadCallStack();

private:
  zz::base::Thread::LocalStorageKey thread_call_stack_key_;
};

#endif