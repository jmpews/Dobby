#include "srcxx/ThreadSupport.h"

CallStack *ThreadSupport::CurrentThreadCallStack() {
  if (zz::base::Thread::HasThreadLocal(thread_call_stack_key_)) {
    return static_cast<CallStack *>(zz::base::Thread::GetThreadLocal(thread_call_stack_key_));
  } else {
    CallStack *call_stack = new CallStack;
    zz::base::Thread::SetThreadLocal(thread_call_stack_key_, call_stack);
    return call_stack;
  }
}
