#include "srcxx/ThreadSupport.h"

zz::Thread::LocalStorageKey ThreadSupport::thread_callstack_key_;

CallStack *ThreadSupport::CurrentThreadCallStack() {
  if (zz::Thread::HasThreadLocal(thread_callstack_key_)) {
    return static_cast<CallStack *>(zz::Thread::GetThreadLocal(thread_callstack_key_));
  } else {
    CallStack *callstack = new CallStack;
    zz::Thread::SetThreadLocal(thread_callstack_key_, callstack);
    return callstack;
  }
}
