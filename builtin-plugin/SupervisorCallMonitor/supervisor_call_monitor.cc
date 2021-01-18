#include "SupervisorCallMonitor/misc_utility.h"
#include "dobby_internal.h"
#include "PlatformUtil/ProcessRuntimeUtility.h"

#include "external_helper/async_logger.h"

#include <vector>
std::vector<DBICallTy> *g_supervisor_call_handlers;

static const char *fast_get_main_app_bundle_udid() {
  auto main = ProcessRuntimeUtility::GetProcessModuleMap()[0];
  char main_binary_path[2048] = {0};
  if(realpath(main.path, main_binary_path) == NULL)
    return NULL;

  char *bundle_udid_ndx = main_binary_path + strlen("/private/var/containers/Bundle/Application/");

  char *result = (char *)malloc(36+1);
  strncpy(result, bundle_udid_ndx, 36);
  result[36] = 0;
  return result;
}

static void common_supervisor_call_monitor_handler(RegisterContext *ctx, const HookEntryInfo *info) {
  for(auto handler : *g_supervisor_call_handlers) {
    handler(ctx, info);
  }
}

void supervisor_call_monitor_register_handler(DBICallTy handler) {
  if (g_supervisor_call_handlers == NULL) {
    g_supervisor_call_handlers = new std::vector<DBICallTy>();
  }
  g_supervisor_call_handlers->push_back(handler);
}

void supervisor_call_monitor_register_svc(addr_t svc_addr) {
  DobbyInstrument((void *)svc_addr, common_supervisor_call_monitor_handler);
  DLOG(2, "register supervisor_call_monitor at %p", svc_addr);
}

void supervisor_call_monitor_register_image(void *header) {
  auto text_section  = macho_kit_get_section_by_name((mach_header_t *)header, "__TEXT", "__text");

  addr_t insn_addr     = (addr_t)header + (addr_t)text_section->offset;
  addr_t insn_addr_end = insn_addr + text_section->size;

  for (; insn_addr < insn_addr_end; insn_addr += sizeof(uint32_t)) {
    if (*(uint32_t *)insn_addr == 0xd4001001) {
      supervisor_call_monitor_register_svc((addr_t)insn_addr);
      LOG(2, "register supervisor_call_monitor at %p", insn_addr);
    }
  }
}

void supervisor_call_monitor_register_main_app() {
  const char *main_bundle_udid = fast_get_main_app_bundle_udid();
  auto module_map = ProcessRuntimeUtility::GetProcessModuleMap();
  for(auto module : module_map) {
    if(strstr(module.path, main_bundle_udid)) {
      supervisor_call_monitor_register_image((void *)module.load_address);
    }
  }
}


void supervisor_call_monitor_init() {
  // create logger file
  char logger_path[1024] = {0};
  sprintf(logger_path, "%s%s", getenv("HOME"), "/Documents/svc_monitor.txt");
  LOG(2, "HOME: %s", logger_path);
  async_logger_init(logger_path);

  dobby_enable_near_branch_trampoline();
}