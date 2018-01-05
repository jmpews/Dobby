// .section	__TEXT,__text,regular,pure_instructions
// .ios_version_min 11, 0

#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

#include "AssembleKit/ARM64/macro_kit.s"

.align 4

.globl cdecl(ctx_save)
.globl cdecl(ctx_restore)
.globl cdecl(enter_thunk_template)
.globl cdecl(leave_thunk_template)
.globl cdecl(on_enter_trampoline_template)
.globl cdecl(on_invoke_trampoline_template)
.globl cdecl(on_leave_trampoline_template)


cdecl(ctx_save):
	// save {q0-q7}
	sub sp, sp, #(8*16)
	stp q6, q7, [sp, #(6*16)]
	stp q4, q5, [sp, #(4*16)]
	stp q2, q3, [sp, #(2*16)]
	stp q0, q1, [sp, #(0*16)]

	// save {x1-x30}
	sub sp, sp, #(30*8)
	// stp fp, lr, [sp, #(28*8)]
	stp x29, x30, [sp, #(28*8)]
	stp x27, x28, [sp, #(26*8)]
	stp x25, x26, [sp, #(24*8)]
	stp x23, x24, [sp, #(22*8)]
	stp x21, x22, [sp, #(20*8)]
	stp x19, x20, [sp, #(18*8)]
	stp x17, x18, [sp, #(16*8)]
	stp x15, x16, [sp, #(14*8)]
	stp x13, x14, [sp, #(12*8)]
	stp x11, x12, [sp, #(10*8)]
	stp x9, x10, [sp, #(8*8)]
	stp x7, x8, [sp, #(6*8)]
	stp x5, x6, [sp, #(4*8)]
	stp x3, x4, [sp, #(2*8)]
	stp x1, x2, [sp, #(0*8)]

	// C6.1.3
	// Use of the stack pointer
	// save x0 (and reserve sp, but this is trick.)
	sub sp, sp, #(2*8)
	str x0, [sp, #8]

cdecl(ctx_restore):
	// C6.1.3
	// Use of the stack pointer
	// restore x0
	ldr x0, [sp, #8]
	add sp, sp, #(2*8)

	// restore {x1-x30}
	ldp x1, x2, [sp], #16
	ldp x3, x4, [sp], #16
	ldp x5, x6, [sp], #16
	ldp x7, x8, [sp], #16
	ldp x9, x10, [sp], #16
	ldp x11, x12, [sp], #16
	ldp x13, x14, [sp], #16
	ldp x15, x16, [sp], #16
	ldp x17, x18, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x27, x28, [sp], #16
	// ldp fp, lr, [sp], #16
	ldp x29, x30, [sp], #16

	// restore {q0-q7}
	ldp q0, q1, [sp], #32
	ldp q2, q3, [sp], #32
	ldp q4, q5, [sp], #32
	ldp q6, q7, [sp], #32

cdecl(enter_thunk_template):
	CTX_SAVE_ALL_MACRO

	// use the `ctx_save` left space, to store origin sp
	add x1, sp, #0x190
	str x1, [sp, #0]

	// alignment padding
	sub sp, sp, #0x10

	// prepare args
	// x0: entry address, x1: next hop, x2: RegState address, x3: caller_ret_addr
	ldr x0, [sp, #0x190]
	add x1, sp, #0x198
	add x2, sp, #0x10
	add x3, sp, #0x108
	// call function_context_begin_invocation
	// .long cdecl(function_context_begin_invocation)
	bl cdecl(function_context_begin_invocation)

	// restore alignment padding
	add sp, sp, #0x10

	CTX_RESTORE_ALL_MACRO

	// jump to next hop
	// next hop addess(store at reserve space)
	ldr x17, [sp, #8]
	add sp, sp, #0x10
	br x17

cdecl(leave_thunk_template):
	CTX_SAVE_ALL_MACRO

	// use the `ctx_save` left space, to store origin sp
	add x1, sp, #0x190
	str x1, [sp, #0]

	// alignment padding
	sub sp, sp, #0x10

	// prepare args
	// x0: entry address, x1: next hop, x2: RegState address
	ldr x0, [sp, #0x190]
	add x1, sp, #0x198
	add x2, sp, #0x10
	// call function_context_end_invocation
	bl cdecl(function_context_end_invocation)

	// restore alignment padding
	add sp, sp, #0x10

	CTX_RESTORE_ALL_MACRO

	// jump to next hop
	// next hop addess(store at reserve space)
	ldr x17, [sp, #8]
	add sp, sp, #0x10
	br x17

cdecl(on_enter_trampoline_template):
	// store entry address and reserve space for next hop
	sub sp, sp, 0x10
	ldr x17, #0x8
	b #0xc
	// entry address
	.long 0x0
	.long 0x0
	str x17, [sp]
	ldr x17, #0x8
	br x17
	// enter_thunk address
	.long 0x0
	.long 0x0

cdecl(on_invoke_trampoline_template):
	// fix instruction
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	ldr x17, #8
	br x17
	.long 0x0
	.long 0x0

cdecl(on_leave_trampoline_template):
	// store entry address and reserve space for next hop
	sub sp, sp, 0x10
	ldr x17, #0x8
	b #0xc
	// entry address
	.long 0x0
	.long 0x0
	str x17, [sp]
	ldr x17, #0x8
	br x17
	// leave_thunk address
	.long 0x0
	.long 0x0

