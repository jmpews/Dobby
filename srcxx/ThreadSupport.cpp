#include "srcxx/ThreadSupport.h"

using namespace zz;

Thread::LocalStorageKey ThreadSupport::thread_callstack_key_ = 0;

// Get current CallStack
CallStack *ThreadSupport::CurrentThreadCallStack() {

  // TODO: __attribute__((destructor)) is better ?
  if (!thread_callstack_key_) {
    thread_callstack_key_ = Thread::CreateThreadLocalKey();
  }

  if (Thread::HasThreadLocal(thread_callstack_key_)) {
    return static_cast<CallStack *>(Thread::GetThreadLocal(thread_callstack_key_));
  } else {
    CallStack *callstack = new CallStack();
    Thread::SetThreadLocal(thread_callstack_key_, callstack);
    return callstack;
  }
}
