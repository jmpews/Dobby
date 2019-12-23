## StaticDobby

StaticDobby is a static file hook tool by modify macho file, which is based on Dobby.

## Compile & Build

#### 1. Build StaticDobby tool

StaticDobby modify and insert an indirect branch stub at the target function which you want to hook. It's not enough, so RuntimeSupport library is necessary at runtime.

```
export DOBBY_SOURCE_DIR=/path/Dobby
cd StaticDobby; mkdir build; cd build
cmake .. -DDOBBY_SOURCE_DIR=${DOBBY_SOURCE_DIR}
make -j4
```

#### 2 Build RuntimeSupport library

The RuntimeSupport library do some auxiliary work and provide interface function(DobbyHookStatic).


#### 2. Static insert indirect branch stub to your binary

`function_vmaddr` is the virtual function address which is the same as the IDA pro show.

```
./MachOStaticPatcher /YourBinaryApp/binary function_vmaddr1 function_vmaddr2
```

## Epilogue

have fun.