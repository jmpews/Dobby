[转到中文README](README_zh-cn.md)

## What is HookZz ?

**a hook framework for arm/arm64/ios/android**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to [frida-gum](https://github.com/frida/frida-gum) perfect code and modular architecture, frida is aircraft carrier, HookZz is boat, but still with some tricks**

**thanks for @lauos with contributing android code**

## Features

- **solidify inlinehook without Jailbreak(Static Binary Instrumentation) [new-90%]**

- **GOT hook with HookZz(i.e. change fishhook to inlinehook), better for APM**

- the power to access registers directly

- hook function with `replace_call`

- hook function with `pre_call` and `post_call`

- hook **address(a piece of instructions)** with `pre_call` and `half_call`

- (almost)only **one instruction** to hook(i.e. hook **short funciton, even only one instruction**) [arm/thumb/arm64]

- runtime code patch, without codesign limit [Jailbreak]

- it's cute, **100kb**

## How it works ?

[Move to HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/docs/HookFrameworkDesign.md)

## Demo

[HookZzAndroidDemoTemplate.zip](https://github.com/jmpews/HookZz/blob/master/demo/HookZzAndroidDemoTemplate.zip)

## Thanks List

@sxf144 - RMB1000

@ckis - RMB88

## Contact Me

```
recommend_email: jmpews@gmail.com
wechat: winter1ife
QQ: 858982985
```

<img with="320px" height="320px" src="http://ww1.sinaimg.cn/large/a4decaedgy1fq5qkcu3cij20iq0owtad.jpg" alt="qrcode">