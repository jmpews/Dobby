[转到中文README](README_zh-cn.md)

## What is HookZz ?

**a hook framework for arm/arm64/ios/android**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to [frida-gum](https://github.com/frida/frida-gum) perfect code and modular architecture, frida is aircraft carrier, HookZz is boat, but still with some tricks**

## Features

- Static Binary Instrumentation for Mach-O [doing]

- GOT hook with `pre_call` & `post_call`

- **replace function** with `replace_call`

- **wrap function** with `pre_call` and `post_call`

- **dynamic binary instrumentation** with `dbi_call`

- the power to hook short function 

- the power to access registers directly(ex: `rs->general.regs.x15`)

- runtime code patch

- it's cute, **100kb**

## Compile

**`git clone --depth 1 git@github.com:jmpews/HookZz.git --branch master-c `**

#### build for iOS/ARM64

```
mkdir build
cd build
cmake 
make
```

if you want generate Xcode Project, just replace with `cmake `

## Usage

#### 1. replace hook function
```
RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call);
```

## Contact Me

```
recommend_email: jmpews@gmail.com
QQ: 858982985
```

<img with="320px" height="320px" src="http://ww1.sinaimg.cn/large/a4decaedgy1fs87lnda3ej20iq0ow0ue.jpg" alt="qrcode">
