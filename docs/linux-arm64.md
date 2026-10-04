# Linux ARM64 compatibility fixes

The Linux ARM64 build needs ELF relocations and the current platform interfaces:

- Use ELF ARM64 page relocations outside Apple builds instead of Mach-O `@PAGE` / `@PAGEOFF` syntax.
- Update Linux process-map code to the current `MemRange::start()` and `RuntimeModule::base` interfaces, handle failed reads, initialize module paths, and distinguish RWX regions before RW regions.
- Include the current cache-flush interface in POSIX code patching.
- Include `<sys/time.h>` directly for `gettimeofday`.
- Define a fallback for `__has_feature` on compilers such as GCC 13.

## Build and smoke test

```sh
sh tests/run-linux-arm64.sh
```

The runner builds both static and shared libraries, then drives real inline hooks through each library: original integer and floating-point calls, relocated trampolines, and five install/remove cycles. It passed on a MacBook Pro 13-inch M1/J293 running Linux 7.1.13 with 16 KiB pages and GCC 16.1.1. The same hook smoke test also passed on a native Ubuntu 24.04 ARM64 runner with GCC 13 and 4 KiB pages. The process-map test checks RWX, RW, and RX mappings, address ordering, module base lookup, and path termination.

`DobbyGetVersion` is declared in this source base's public header but is not supplied by the static build; the test does not rely on it. Existing compiler deprecation/attribute warnings remain non-fatal in the tested build.
