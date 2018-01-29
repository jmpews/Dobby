## MachoParser

parse macho with multiple input.

#### 1. parse with file

```C
MachoFD fd;
if (!fd.setPath("/Users/jmpews/Desktop/SpiderZz/project/MachoParser/build/x86/test_objc")) {
    Serror("open error.");
    return;
}
fd.parse_macho();
if (fd.isFat) {
    MachoFD *xfd = new MachoFD();
    xfd = (MachoFD *) fd.parse_macho_arch(CPU_TYPE_X86_64);
    xfd->parse_macho();
}
```

#### 2. parse with pid

support with `vm_read_overwrite` and `task_for_pid`

```C
MachoTask rt;
rt.setPid(47255);
rt.parse_macho();
```

#### 3. parse with self process

build for `.dylib`, and use `DYLD_INSERT_LIBRARIES` to inject the dylib.

btw: with the hook of `objc_msgSend`, trace the objective-c method calling, will be better.

```C
__attribute__((constructor)) void parse_self() {
    MachoMem *mem = new MachoMem();
    mem.parse_macho()
}
```


## compile & use

```
λ : >>> make -f darwin.ios.mk darwin.ios
generate [src/MachoFD.o]!
generate [src/MachoMem.o]!
generate [src/MachoTask.o]!
generate [src/macho.o]!
generate [src/parsers/Header.o]!
generate [src/parsers/LoadCommand.o]!
generate [src/parsers/ObjcRuntime.o]!
generate [src/parsers/Section.o]!
generate [src/objc/oobjc.o]!
generate [src/zzdeps/darwin/memory-utils-darwin.o]!
build success for arm64(IOS)!
```