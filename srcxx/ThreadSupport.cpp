#include "srcxx/ThreadSupport.h"

static void ThreadSupport::PushStackFrame(StackFrame *stackframe) {
  CallStack *callstack = static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_callstack_key_));
  callstack->stackframes.push_back(stackframe);
}

static StackFrame *ThreadSupport::PopStackFrame() {
  CallStack *callstack = static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_callstack_key_));
  StackFrame *stackframe =  callstack->stackframes.back();
  callstack->stackframes.pop_back();
  return stackframe;
}

static void ThreadSupport::SetStackFrameContextValue(StackFrame *stackframe, const char *key, const void *value) {
  std::map<char *, void *> *kv_context = &stackframe->kv_context;
  kv_context->insert(std::pair<char *, void *>(key, value));
};

static void *ThreadSupport::GetStackFrameContextValue(StackFrame *stackframe, const char *key) {
  std::map<char *, void *> kv_context = stackframe->kv_context;
  std::map<char *, void *>::iterator it;
  it = kv_context.find(key);
  if (it != kv_context.end()) {
    return (void *)it->second;
  }
  return NULL;
};

CallStack *ThreadSupport::CurrentThreadCallStack() {
  if (zz::base::Thread::HasThreadLocal(thread_callstack_key_)) {
    return static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_callstack_key_));
  } else {
    CallStack *callstack = new CallStack;
    zz::base::Thread::SetThreadLocal(thread_callstack_key_, callstack);
    return callstack;
  }
}
