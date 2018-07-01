# HookZz Framework

# Hook Framework

一般来说可以分为以下几个模块

1. 内存分配 模块
2. 指令写 模块
3. 指令读 模块
4. 指令修复 模块
5. 跳板 模块
6. 调度器 模块
7. 栈 模块

## 1. 内存分配 模块

这里主要关注三个点:

1. 内存的分配
2. 内存属性修改
3. 内存布局获取

#### 1.1 内存的分配

**设计方面:** 1. 提供一个 allocator 去管理/分配内存 2. 需要封装成架构无关的 API.

通常使用 posix 标准的 `mmap`, darwin 下的 mach kernel 分配内存使用 `mmap` 实际使用的是 `mach_vm_allocate`. [move to detail]( https://github.com/bminor/glibc/blob/master/sysdeps/mach/hurd/mmap.c)

在入口点的 patch, 通常会使用绝对地址跳到 `trampoline`, 如果使用绝对地址跳, 将会占用 4 条指令, 如下的形式.

```
ldr x17, #0x8
b #0xc
.long 0x0
.long 0x0
br x17
```

但是如果可以使用 `B #0x?`, 实现相对地址跳(near jump), 将是最好的, 在 armv8 中的可以想在 `+-128MB` 范围内进行 `near jump`, 具体可以参考 `ARM Architecture Reference Manual ARMv8, for ARMv8-A architecture profile Page: C6-550`. 所以问题转换为找到一块 `rx-` 的内存写入 enter trampline. 

大概有以下几种方法可以获取到 `rx-` 内存块.

1. 尝试使用 mmap 的 fixed flag 分配相近内存

2. 当时获取进程内的所有动态库列表, 之后搜索每一个动态库的 `__TEXT`, 查找是否存在 code cave.(尝试搜索内存空洞(`code cave`), 搜索 `__text` 这个 `section` 其实更准确来说是搜索 `__TEXT` 这个 `segment`. 由于内存页对齐的原因以及其他原因很容易出现 `code cave`. 所以只需要搜索这个区间内的 `00` 即可, `00` 本身就是无效指令, 所以可以判断该位置无指令使用.)

3. 获取当前进程的内存布局, 对所有 `rx-` 属性内存页搜索 code cave. (内存布局的获取会在1.3详细提到)

#### 1.2 内存属性修改

通常使用 posix 标准的 `mprotect`, darwin 下的 mach kernel 修改内存属性使用的是 `mach_vm_protect`, 注意: ios 不允许引用 `#include <mach_vm.h>`, 可以用单独拷贝一份该头文件到项目下.

这一部分与具体的操作系统有关. 比如 .

在 lldb 中可以通过 `memory region address` 查看地址的内存属性.

当然这里也存在一个巨大的坑, ios 下无法分配 `rwx` 属性的内存页. 这导致 inlinehook 无法在非越狱系统上使用, 并且只有 `MobileSafari` 才有 `VM_FLAGS_MAP_JIT` 权限. 具体解释请参下方 **[坑 - rwx 与 codesigning]**.

#### 1.3 内存布局获取

#### 2. 指令写 模块

#### 3. 指令读 模块

#### 4. 指令修复 模块

#### 5. 跳板 模块

#### 6. 调度 模块

#### 7. 栈模块


# 坑

## `ldr` 指令

在进行指令修复时, 需要需要将 PC 相关的地址转换为绝对地址, 其中涉及到保存地址到寄存器. 一般来说是使用指令 `ldr`. 

`frida-gum` 的实现原理是, 有一个相对地址表, 保存所有用到的 ldr 指令的地方, 默认 ldr 取得都是 0 相对便宜(b 等相对指令也有记录), 在指令修复后有一个 flush writer 的过程, 这个过程会把, 会将用到绝对地址写到整个指令块后面, 形成一个绝对地址表, 同时修复之前 ldr 引用的相对偏移.

```
gboolean
gum_arm64_writer_put_ldr_reg_u64 (GumARM64Writer * self,
                                  arm64_reg reg,
                                  guint64 val)
{
  GumARM64RegInfo ri;

  gum_arm64_writer_describe_reg (self, reg, &ri);

  if (ri.width != 64)
    return FALSE;

  if (!gum_arm64_writer_add_literal_reference_here (self, val))
    return FALSE;

  gum_arm64_writer_put_instruction (self,
      (ri.is_integer ? 0x58000000 : 0x5c000000) | ri.index);

  return TRUE;
}
```

在 HookZz 中的实现, 直接将地址写在指令后, 之后使用 `b` 到正常的下一条指令, 从而实现将地址保存到寄存器, 这种方式有好有坏.

也就是下面的样子.

```
__asm__ {
	"ldr x17, #0x8\n"
	"b #0xc\n"
	".long\n"
	".long\n"
	"br x17"
}
```

## 寄存器污染

在构建跳板桥的过程, 通常会以以下模板进行跳转.

```
0x0000:  ldr x16, 8;
0x0004:  br x16;
0x0008:  0x4321
0x000c:  0x8765
```

问题在于这会造成 `x16` 寄存器被污染(ARM64 中 `svc #0x80` 使用 `x16` 传递系统调用号) 所以这里有两种思路解决这个问题.

思路一:

在使用寄存器之前进行 `push`, 跳转后 `pop`, 这里存在一个问题就是在原地址的几条指令进行 `patch code` 时一定会污染一个寄存器(也不能说一定, 如果这时进行压栈, 在之后的 `invoke_trampline` 会导致函数栈发生改变, 此时有个解决方法可以 `pop` 出来, 由 hook-entry 或者其他变量暂时保存, 但这时需要处理锁的问题. )

思路二:

挑选合适的寄存器, 不考虑污染问题. 这时可以参考, 下面的资料, 选择 x16 or x17, 或者自己做一个实验 `otool -tv ~/Downloads/xxx > ~/Downloads/xxx.txt` 通过 dump 一个 `ARM64` 程序的指令, 来判断哪个寄存器用的最少, 但是不要使用 `x18` 寄存器, 你对该寄存器的修改是无效的.

参考资料:

```
PAGE: 9-3
Programmer’s Guide for ARMv8-A
9.1 Register use in the AArch64 Procedure Call Standard 
9.1.1 Parameters in general-purpose registers
```

## `rwx` 与 `codesigning`

对于非越狱, 不能分配可执行内存, 不能进行 `code patch`.

两篇原理讲解 codesign 的原理

```
https://papers.put.as/papers/ios/2011/syscan11_breaking_ios_code_signing.pdf
http://www.newosxbook.com/articles/CodeSigning.pdf
```

以及源码分析如下:

crash 异常如下, 其中 `0x0000000100714000` 是 mmap 分配的页.

```
Exception Type:  EXC_BAD_ACCESS (SIGKILL - CODESIGNING)
Exception Subtype: unknown at 0x0000000100714000
Termination Reason: Namespace CODESIGNING, Code 0x2
Triggered by Thread:  0
```

寻找对应的错误码

```
xnu-3789.41.3/bsd/sys/reason.h
/*
 * codesigning exit reasons
 */
#define CODESIGNING_EXIT_REASON_TASKGATED_INVALID_SIG 1
#define CODESIGNING_EXIT_REASON_INVALID_PAGE          2
#define CODESIGNING_EXIT_REASON_TASK_ACCESS_PORT      3
```

找到对应处理函数, 请仔细阅读注释里内容, 不做解释了.

```
# xnu-3789.41.3/osfmk/vm/vm_fault.c:2632

	/* If the map is switched, and is switch-protected, we must protect
	 * some pages from being write-faulted: immutable pages because by 
	 * definition they may not be written, and executable pages because that
	 * would provide a way to inject unsigned code.
	 * If the page is immutable, we can simply return. However, we can't
	 * immediately determine whether a page is executable anywhere. But,
	 * we can disconnect it everywhere and remove the executable protection
	 * from the current map. We do that below right before we do the 
	 * PMAP_ENTER.
	 */
	cs_enforcement_enabled = cs_enforcement(NULL);

	if(cs_enforcement_enabled && map_is_switched && 
	   map_is_switch_protected && page_immutable(m, prot) && 
	   (prot & VM_PROT_WRITE))
	{
		return KERN_CODESIGN_ERROR;
	}

	if (cs_enforcement_enabled && page_nx(m) && (prot & VM_PROT_EXECUTE)) {
		if (cs_debug)
			printf("page marked to be NX, not letting it be mapped EXEC\n");
		return KERN_CODESIGN_ERROR;
	}

	if (cs_enforcement_enabled &&
	    !m->cs_validated &&
	    (prot & VM_PROT_EXECUTE) &&
	    !(caller_prot & VM_PROT_EXECUTE)) {
		/*
		 * FOURK PAGER:
		 * This page has not been validated and will not be
		 * allowed to be mapped for "execute".
		 * But the caller did not request "execute" access for this
		 * fault, so we should not raise a code-signing violation
		 * (and possibly kill the process) below.
		 * Instead, let's just remove the "execute" access request.
		 * 
		 * This can happen on devices with a 4K page size if a 16K
		 * page contains a mix of signed&executable and
		 * unsigned&non-executable 4K pages, making the whole 16K
		 * mapping "executable".
		 */
		prot &= ~VM_PROT_EXECUTE;
	}

	/* A page could be tainted, or pose a risk of being tainted later.
	 * Check whether the receiving process wants it, and make it feel
	 * the consequences (that hapens in cs_invalid_page()).
	 * For CS Enforcement, two other conditions will 
	 * cause that page to be tainted as well: 
	 * - pmapping an unsigned page executable - this means unsigned code;
	 * - writeable mapping of a validated page - the content of that page
	 *   can be changed without the kernel noticing, therefore unsigned
	 *   code can be created
	 */
	if (!cs_bypass &&
	    (m->cs_tainted ||
	     (cs_enforcement_enabled &&
	      (/* The page is unsigned and wants to be executable */
	       (!m->cs_validated && (prot & VM_PROT_EXECUTE))  ||
	       /* The page should be immutable, but is in danger of being modified
		* This is the case where we want policy from the code directory -
		* is the page immutable or not? For now we have to assume that 
		* code pages will be immutable, data pages not.
		* We'll assume a page is a code page if it has a code directory 
		* and we fault for execution.
		* That is good enough since if we faulted the code page for
		* writing in another map before, it is wpmapped; if we fault
		* it for writing in this map later it will also be faulted for executing 
		* at the same time; and if we fault for writing in another map
		* later, we will disconnect it from this pmap so we'll notice
		* the change.
		*/
	      (page_immutable(m, prot) && ((prot & VM_PROT_WRITE) || m->wpmapped))
	      ))
		    )) 
	{
```

#### 其他文章:

http://ddeville.me/2014/04/dynamic-linking

> Later on, whenever a page fault occurs the vm_fault function in `vm_fault.c` is called. During the page fault the signature is validated if necessary. The signature will need to be validated if the page is mapped in user space, if the page belongs to a code-signed object, if the page will be writable or simply if it has not previously been validated. Validation happens in the `vm_page_validate_cs` function inside vm_fault.c (the validation process and how it is enforced continually and not only at load time is interesting, see Charlie Miller’s book for more details).

> If for some reason the page cannot be validated, the kernel checks whether the `CS_KILL` flag has been set and kills the process if necessary. There is a major distinction between iOS and OS X regarding this flag. All iOS processes have this flag set whereas on OS X, although code signing is checked it is not set and thus not enforced.

> In our case we can safely assume that the (missing) code signature couldn’t be verified leading to the kernel killing the process.

---