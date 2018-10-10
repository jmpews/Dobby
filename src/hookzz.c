#include "hookzz.h"
#include "core.h"
#include "hookzz_internal.h"
#include "interceptor.h"
#include "interceptor_routing_trampoline.h"
#include "std_kit/std_kit.h"

bool g_near_jump_flag = false;

void zz_enable_near_jump() {
  g_near_jump_flag = true;
}

bool zz_is_near_jump() {
  return g_near_jump_flag;
}

void zz_disable_near_jump() {
  g_near_jump_flag = false;
}

static void initialize_hook_entry(hook_entry_t *entry) {

  if (zz_is_near_jump()) {
    entry->is_try_near_jump = true;
  }

  interceptor_t *interceptor = interceptor_cclass(shared_instance)();
  interceptor_cclass(add_hook_entry)(interceptor, entry);
  interceptor_trampoline_cclass(build_all)(entry);
  interceptor_trampoline_cclass(active)(entry);
}

RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call) {
  hook_entry_t *entry   = SAFE_MALLOC_TYPE(hook_entry_t);
  entry->id             = (uintptr_t)entry;
  entry->target_address = function_address;
  entry->type           = HOOK_TYPE_FUNCTION_via_PRE_POST;
  entry->pre_call       = pre_call;
  entry->post_call      = post_call;

  Logging("[*] prepare ZzWrap hook %p", function_address);

  initialize_hook_entry(entry);

  return RS_SUCCESS;
}

RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call) {
  hook_entry_t *entry   = SAFE_MALLOC_TYPE(hook_entry_t);
  entry->id             = (uintptr_t)entry;
  entry->target_address = function_address;
  entry->type           = HOOK_TYPE_FUNCTION_via_REPLACE;
  entry->replace_call   = replace_call;

  Logging("[*] prepare ZzReplace hook %p", function_address);

  initialize_hook_entry(entry);

  *origin_call = entry->on_invoke_trampoline;

  return RS_SUCCESS;
}

RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL dbi_call) {
  hook_entry_t *entry   = SAFE_MALLOC_TYPE(hook_entry_t);
  entry->id             = (uintptr_t)entry;
  entry->target_address = inst_address;
  entry->type           = HOOK_TYPE_INSTRUCTION_via_DBI;
  entry->dbi_call       = dbi_call;

  Logging("[*] prepare ZzDynamicBinaryInstrumentation hook %p", inst_address);

  initialize_hook_entry(entry);

  return RS_SUCCESS;
}
