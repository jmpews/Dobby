#if defined(ENABLE_CLOSURE_BRIDGE_TEMPLATE)

#if defined(__WIN32__) || defined(__APPLE__)
#define xcdecl(s) "_" s
#else
#define xcdecl(s) s
#endif

#define xASM(x) __asm(x)

__attribute__((naked)) void closure_bridge_template() {
  // flags register
  xASM("pushfq");

  // general register
  xASM("sub rsp, #(16*8)");
  xASM("mov [rsp+16*0], rax");
  xASM("mov [rsp+16*1], rbx");
  xASM("mov [rsp+16*2], rcx");
  xASM("mov [rsp+16*3], rdx");
  xASM("mov [rsp+16*4], rbp");
  xASM("mov [rsp+16*5], rsp");
  xASM("mov [rsp+16*6], rdi");
  xASM("mov [rsp+16*7], rsi");
  xASM("mov [rsp+16*8], r8");
  xASM("mov [rsp+16*9], r9");
  xASM("mov [rsp+16*10], r10");
  xASM("mov [rsp+16*11], r11");
  xASM("mov [rsp+16*12], r12");
  xASM("mov [rsp+16*13], r13");
  xASM("mov [rsp+16*14], r14");
  xASM("mov [rsp+16*15], r15");

  // ======= Jump to Common Bridge Handle =======

  // prepare args
  // @rdi: data_address
  // @rsi: RegisterContext stack address
  xASM("mov x0, sp");
  xASM("mov x1, x14");
  xASM("call " xcdecl("intercept_routing_common_bridge_handler"));

  // ======= RegisterContext Restore =======
  // restore x0
  xASM("ldr x0, [sp, #8]");
  xASM("add sp, sp, #(2*8)");

  // restore {x1-x30}
  xASM("ldp x1, x2, [sp], #16");
  xASM("ldp x3, x4, [sp], #16");
  xASM("ldp x5, x6, [sp], #16");
  xASM("ldp x7, x8, [sp], #16");
  xASM("ldp x9, x10, [sp], #16");
  xASM("ldp x11, x12, [sp], #16");
  xASM("ldp x13, x14, [sp], #16");
  xASM("ldp x15, x16, [sp], #16");
  xASM("ldp x17, x18, [sp], #16");
  xASM("ldp x19, x20, [sp], #16");
  xASM("ldp x21, x22, [sp], #16");
  xASM("ldp x23, x24, [sp], #16");
  xASM("ldp x25, x26, [sp], #16");
  xASM("ldp x27, x28, [sp], #16");
  // ldp fp, lr, [sp], #16");
  xASM("ldp x29, x30, [sp], #16");

  // restore {q0-q7}
  xASM("ldp q0, q1, [sp], #32");
  xASM("ldp q2, q3, [sp], #32");
  xASM("ldp q4, q5, [sp], #32");
  xASM("ldp q6, q7, [sp], #32");

  // DO NOT USE epilog
  // x29 == fp, x30 == lr
  // xASM("mov sp, x29");
  // xASM("ldp x29, x30, [sp], #16");

  xASM("br x15");
};

#endif