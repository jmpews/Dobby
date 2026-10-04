#include "PlatformUtil/ProcessRuntime.h"
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <initializer_list>
#include <sys/mman.h>
#include <unistd.h>

static void check(bool condition, const char* message) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", message);
    std::exit(1);
  }
  std::printf("PASS: %s\n", message);
}

int main() {
  const size_t page = sysconf(_SC_PAGESIZE);
  std::printf("Linux process-map smoke test; page size %zu\n", page);
  for (int permission : {PROT_READ | PROT_WRITE | PROT_EXEC, PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC}) {
    void* mapping = mmap(nullptr, page, permission, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(mapping != MAP_FAILED, "create a test mapping");
    bool found = false;
    const auto address = reinterpret_cast<addr_t>(mapping);
    const auto& regions = ProcessRuntime::getMemoryLayout();
    addr_t previous = 0;
    bool sorted = true;
    for (const auto& region : regions) {
      sorted = sorted && region.start() >= previous;
      previous = region.start();
      if (region.start() <= address && address < region.end()) {
        check(region.perm == permission, "mapping retains its read/write/execute permissions");
        found = true;
      }
    }
    check(sorted, "process maps are sorted by address");
    check(found, "process maps contain the allocated page");
    check(munmap(mapping, page) == 0, "release the test mapping");
  }

  char executable[4096] = {};
  const auto length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
  check(length > 0 && static_cast<size_t>(length) < sizeof(executable) - 1, "resolve the executable path");
  executable[length] = '\0';
  const auto module = ProcessRuntime::getModule(executable);
  Dl_info info = {};
  check(dladdr(reinterpret_cast<void*>(main), &info) != 0, "resolve the loader's executable base");
  check(module.base == info.dli_fbase, "module lookup returns the executable load base");
  check(module.path[sizeof(module.path) - 1] == '\0', "module path is terminated");
}
