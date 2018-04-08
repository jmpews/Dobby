## HookZz 简介

一款适用于 arm/arm64 架构, 针对 ios/android 的 Hook 框架.

代码上借鉴了 [frida-gum](https://github.com/frida/frida-gum) & [minhook](https://github.com/TsudaKageyu/minhook) & [substrate](https://github.com/jevinskie/substrate)

这里特别感谢 [frida-gum](https://github.com/frida/frida-gum), `frida-gum` 具有非常优秀的代码架构和精妙的代码, 与 `frida-gum` 这个庞大的航空母舰相比, `HookZz` 太弱小. 但有时候也许你可能只是需要一把锋利的小刀.

这里特别感谢 @lauos 贡献部分的 android 代码.

## 特点

- **静态化Hook aka 静态二进制插桩, 可以静态 Patch 文件**
- **GOT Hook 但执行 HookZz 的流程, 对 APM 有帮助**
- 可以操作寄存器的能力
- 直接替换函数
- 为目标函数添加 `pre_call` 和 `post_call` 处理
- 动态插桩 aka 指令级Hook
- 动态代码Patch
- 很小 aka 100kb

## HookZz 原理

可以参考文档 [HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/docs/HookFrameworkDesign.md)

## Demo 工程

可以参考 [HookZzAndroidDemoTemplate.zip](https://github.com/jmpews/HookZz/blob/master/demo/HookZzAndroidDemoTemplate.zip)


## 联系我

```
recommend_email: jmpews@gmail.com
wechat: winter1ife
QQ: 858982985
```

<img with="320px" height="320px" src="http://ww1.sinaimg.cn/large/a4decaedgy1fq5qkcu3cij20iq0owtad.jpg" alt="qrcode">