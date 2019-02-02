
#include "hookzz_internal.h"

#include "logging/logging.h"

#include "intercept_routing_handler.h"
#include "MultiThreadSupport/ThreadSupport.h"

#include "InterceptRoutingPlugin/intercept-routing-handler/intercept_routing_common_handler.h"

void pre_call_forward_handler(RegisterContext *reg_ctx, HookEntry *entry) {
  DLOG("%s\n", "[*] catch pre_call_forward_handler");
  StackFrame *stackframe = new StackFrame();
  // create stack frame as common variable between pre_call and post_call
  ThreadSupport::PushStackFrame(stackframe);

  // run the `pre_call` before execute origin function which has been relocated(fixed)
  if (entry->pre_call) {
    PRECALL pre_call;
    HookEntryInfo entry_info;
    entry_info.hook_id        = entry->id;
    entry_info.target_address = entry->target_address;
    pre_call                  = entry->pre_call;
    // run the pre_call with the power of accessing all registers
    (*pre_call)(reg_ctx, &entry_info);
  }

  // save the origin ret address, and use in `post_call_forword_handler`
  stackframe->orig_ret = get_func_ret_address(reg_ctx);

  // set the prologue bridge next hop address with the patched instructions has been relocated
  set_routing_bridge_next_hop(reg_ctx, entry->relocated_origin_function);

  // replace the function ret address with our epilogue_routing_dispatch
  set_func_ret_address(reg_ctx, entry->epilogue_dispatch_bridge);
}

void post_call_forward_handler(RegisterContext *reg_ctx, HookEntry *entry) {
  // pop stack frame as common variable between pre_call and post_call
  StackFrame *stackframe = ThreadSupport::PopStackFrame();

  // run the `post_call`, and access all the register value, as the origin function done,
  if (entry->post_call) {
    POSTCALL post_call;
    HookEntryInfo entry_info;
    entry_info.hook_id        = entry->id;
    entry_info.target_address = entry->target_address;
    post_call                 = entry->post_call;

    // run the post_call with the power of accessing all registers
    (*post_call)(reg_ctx, (const HookEntryInfo *)&entry_info);
  }

  // set epilogue bridge next hop address with origin ret address, restore the call.
  set_routing_bridge_next_hop(reg_ctx, stackframe->orig_ret);
}

// run the user handler **before run the origin-instructions(which have been relocated)**
void prologue_routing_dispatch(RegisterContext *reg_ctx, ClosureTrampolineEntry *closure_trampoline_entry) {
  DLOG("%s\n", "[*] catch prologue dispatch");
  HookEntry *entry = static_cast<HookEntry *>(closure_trampoline_entry->carry_data);
  pre_call_forward_handler(reg_ctx, entry);
  return;
}

// run the user handler **before the function return** by replace the lr register
void epilogue_routing_dispatch(RegisterContext *reg_ctx, ClosureTrampolineEntry *closure_trampoline_entry) {
  DLOG("%s\n", "[*] catch epilogue dispatch");
  HookEntry *entry = static_cast<HookEntry *>(closure_trampoline_entry->carry_data);
  post_call_forward_handler(reg_ctx, entry);
  return;
}

// Closure bridge branch here unitily, then  common_bridge_handler will dispatch to other handler.
void intercept_routing_common_bridge_handler(RegisterContext *reg_ctx, ClosureTrampolineEntry *entry) {
  DLOG("[*] catch common bridge handler, carry data: %p, carry handler: %p\n",
       ((HookEntry *)entry->carry_data)->target_address, entry->carry_handler);
  USER_CODE_CALL UserCodeCall = (USER_CODE_CALL)entry->carry_handler;
  UserCodeCall(reg_ctx, entry);
  return;
}
