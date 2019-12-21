#### fopen monitor at macOS

1. set env variable at the terminal

```
export DYLD_FORCE_FLAT_NAMESPACE=1
export DYLD_INSERT_LIBRARIES=/Users/jmpews/Z/project/Dobby/examples/HOST.X86_64.build/lib_fopen_monitor.dylib
```

2. open any application

```
/Applications/DingTalk.app/Contents/MacOS/DingTalk
```

3. console
