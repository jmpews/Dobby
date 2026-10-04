#include <dobby.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

static volatile int bias = 7;
static int (*originalInteger)(int) = nullptr;
static double (*originalFloat)(double, double) = nullptr;

__attribute__((noinline)) static int integerTarget(int value) { return value + bias; }
__attribute__((noinline)) static double floatTarget(double x, double y) { return x * y + bias; }

static int integerHook(int value) { return originalInteger(value) + 100; }
static double floatHook(double x, double y) { return originalFloat(x, y) + 100.0; }

static void check(bool condition, const char* name) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", name);
    std::exit(1);
  }
  std::printf("PASS: %s\n", name);
}

int main() {
  std::printf("ARM64 hook smoke test; page size %ld\n", sysconf(_SC_PAGESIZE));
  int (*volatile integerCall)(int) = integerTarget;
  double (*volatile floatCall)(double, double) = floatTarget;
  check(integerCall(3) == 10, "baseline integer call");
  check(floatCall(2.0, 3.0) == 13.0, "baseline floating-point call");
  for (int i = 0; i < 5; ++i) {
    void* original = nullptr;
    check(DobbyHook(reinterpret_cast<void*>(integerTarget), reinterpret_cast<void*>(integerHook), &original) == 0, "install integer hook");
    originalInteger = reinterpret_cast<int (*)(int)>(original);
    check(integerCall(3) == 110, "hook preserves relocated original and integer arguments");
    check(DobbyDestroy(reinterpret_cast<void*>(integerTarget)) == 0, "remove integer hook");
    check(integerCall(3) == 10, "original integer code restored");

    check(DobbyHook(reinterpret_cast<void*>(floatTarget), reinterpret_cast<void*>(floatHook), &original) == 0, "install floating-point hook");
    originalFloat = reinterpret_cast<double (*)(double, double)>(original);
    check(floatCall(2.0, 3.0) == 113.0, "hook preserves floating-point arguments and return");
    check(DobbyDestroy(reinterpret_cast<void*>(floatTarget)) == 0, "remove floating-point hook");
    check(floatCall(2.0, 3.0) == 13.0, "original floating-point code restored");
  }
}
