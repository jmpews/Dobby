## HookZz

hook framwork. ref with: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate)

** still developing**

## 通用Hook结构设计

1. 内存分配 模块
2. 指令写 模块
3. 指令读 模块
4. 指令修复 模块
5. 跳板 模块
6. 调度器 模块

#### 内存分配 模块

需要分配部分内存用于写入指令, 这里需要关注两个函数都是关于内存属性相关的. 1. 如何使内存 `可写` 2. 如何使内存 `可执行`

这一部分与具体的操作系统有关.

在 lldb 中可以通过 `memory region address` 查看地址的内存属性.

#### 指令写 模块

由于现在大部分的 `assembler` 需要 llvm 的支持. 所以并没有现成的框架支持. 其实这里的指令写有种简单的方法, 就是在本地生成指令的16进制串, 之后直接写即可. 但这种应该是属于 hardcode.

这里使用 `frida` 和 `CydiaSubstrace` 都用的方法, 把需要用到的指令都写成一个小函数.

例如:

```
void
gum_arm64_writer_put_ldr_reg_address (GumArm64Writer * self,
                                      arm64_reg reg,
                                      GumAddress address)
{
  gum_arm64_writer_put_ldr_reg_u64 (self, reg, (guint64) address);
}

void
gum_arm64_writer_put_ldr_reg_u64 (GumArm64Writer * self,
                                  arm64_reg reg,
                                  guint64 val)
{
  GumArm64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  g_assert_cmpuint (ri.width, ==, 64);

  gum_arm64_writer_add_literal_reference_here (self, val);
  gum_arm64_writer_put_instruction (self,
      (ri.is_integer ? 0x58000000 : 0x5c000000) | ri.index);
}

```

##### 指令读 模块

这一部分实际上就是 `disassembler`, 这一部分可以直接使用 `capstone`, 这里需要把 `capstone` 编译成多种架构.

#### 指令修复 模块

这里的指令修复主要是发生在 hook 函数头几条指令, 由于备份指令到另一个地址, 这就需要对所有 `PC(IP)` 相关指令进行修复.

大致的思路就是: 判断 `capstone` 读取到的指令 ID, 针对特定指令写一个小函数进行修复

例如在 `frida-gum` 中:

```
static gboolean
gum_arm64_relocator_rewrite_b (GumArm64Relocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm64_op * target = &ctx->detail->operands[0];

  (void) self;

  gum_arm64_writer_put_ldr_reg_address (ctx->output, ARM64_REG_X16,
      target->imm);
  gum_arm64_writer_put_br_reg (ctx->output, ARM64_REG_X16);

  return TRUE;
}
```

#### 跳板 模块

跳板模块的设计是希望各个模块的实现更浅的耦合, 跳板模块本意只实现跳转指令.

#### 中心调度 模块

这一步其实有无即可, 都不影响基本功能, 但为之后的其他工作打下基础.

本质有些类似于 `objc_msgSend` 所有的被 hook 的函数都在经过 `enter_trampoline` 跳板后, 跳转到 `enter_thunk`, 在此进行下一步的跳转判断决定, 并不是直接跳转到 `replace_call`.

#### 逻辑上

同时逻辑上, 应该具有以下:

hook结构描述, hook结构记录