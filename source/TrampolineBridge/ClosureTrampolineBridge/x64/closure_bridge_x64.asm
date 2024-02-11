#if defined(__x86_64__)
#if defined(__WIN32__) || defined(__APPLE__)
#define cdecl(s) _##s
#else
#define cdecl(s) s
#endif

.intel_syntax noprefix
.align 4

.globl cdecl(closure_bridge_asm)
cdecl(closure_bridge_asm):
  // flags register
  pushfq
  // used for alignment
  sub rsp, 8

  // general register
  sub rsp, 16*8
  mov [rsp+8*0], rax
  mov [rsp+8*1], rbx
  mov [rsp+8*2], rcx
  mov [rsp+8*3], rdx
  mov [rsp+8*4], rbp
  mov [rsp+8*5], rsp
  mov [rsp+8*6], rdi
  mov [rsp+8*7], rsi
  mov [rsp+8*8], r8
  mov [rsp+8*9], r9
  mov [rsp+8*10], r10
  mov [rsp+8*11], r11
  mov [rsp+8*12], r12
  mov [rsp+8*13], r13
  mov [rsp+8*14], r14
  mov [rsp+8*15], r15

#define rsp_offset (8*5)
#define orig_rsp_offset (16*8+2*8+8)
  mov rax, rsp
  add rax, orig_rsp_offset // include `closure_tramp_entry_addr` stack var
  mov [rsp+rsp_offset], rax

  // call convention: rdi = register context, rsi = interceptor entry
#define closure_tramp_entry_offset (16*8+2*8)
  mov rdi, rsp
  mov rsi, [rsp+closure_tramp_entry_offset]

  mov rax, rsp
  and rax, 0xf
  jz .Lstack_aligned_call_start
  push rax
  call cdecl(common_closure_bridge_handler)
  pop rax
  jmp .Lcall_end

  .Lstack_aligned_call_start:
  call cdecl(common_closure_bridge_handler)
  .Lcall_end:

  // general register
  pop rax
  pop rbx
  pop rcx
  pop rdx
  pop rbp
  add rsp, 8
  pop rdi
  pop rsi
  pop r8
  pop r9
  pop r10
  pop r11
  pop r12
  pop r13
  pop r14
  pop r15

  // used for alignment
  add rsp, 8
  // flags register
  popfq

  // trick: use `closure_tramp_entry_addr` stack_addr to store the return address
  ret

.globl cdecl(closure_bridge_asm_end)
cdecl(closure_bridge_asm_end):

.data
.align 8
common_closure_bridge_handler_addr:
.quad cdecl(common_closure_bridge_handler)
#endif