#include "platform_detect_macro.h"

#if defined(TARGET_ARCH_ARM64)

#include "InstructionRelocation/arm64/InstructionRelocationARM64.h"

#include "dobby/dobby_internal.h"

#include "core/arch/arm64/registers-arm64.h"
#include "core/assembler/assembler-arm64.h"
#include "core/codegen/codegen-arm64.h"

#include "inst_constants.h"
#include "inst_decode_encode_kit.h"

using namespace zz::arm64;

#if defined(DOBBY_DEBUG)
#define debug_nop() _ nop()
#else
#define debug_nop()
#endif

#define arm64_trunc_page(x) ((x) & (~(0x1000 - 1)))
#define arm64_round_page(x) trunc_page((x) + (0x1000 - 1))

#if 0
bool has_relo_label_at(relo_ctx_t *ctx, addr_t addr) {
  if (ctx->label_map.count(addr)) {
    return true;
  }
  return false;
}

PseudoLabel *relo_label_create_or_get(relo_ctx_t *ctx, addr_t addr) {
  if (!ctx->label_map.count(addr)) {
    auto *label = new PseudoLabel(addr);
    ctx->label_map[addr] = label;
  }
  return ctx->label_map[addr];
}

int64_t relo_label_link_offset(relo_ctx_t *ctx, pcrel_type_t pcrel_type, int64_t offset) {
  auto is_offset_undefined = [ctx](int64_t offset) -> bool {
    if (ctx->buffer_cursor + offset < ctx->buffer || ctx->buffer_cursor + offset > ctx->buffer + ctx->buffer_size) {
      return true;
    }
    return false;
  };

  auto is_offset_uninitialized = [ctx](int64_t offset) -> bool {
    if (ctx->buffer_cursor + offset > ctx->buffer && ctx->buffer_cursor + offset < ctx->buffer + ctx->buffer_size) {
      if (!ctx->relocated_offset_map.count(ctx->buffer_cursor + offset - ctx->buffer_cursor))
        return true;
    }
    return false;
  };

  addr_t label_vmaddr = relo_cur_src_vmaddr(ctx) + offset;
  if (pcrel_type == RELO_ARM64_RELOC_PAGE21) {
    label_vmaddr = arm64_trunc_page(label_vmaddr);
  }

  auto *label = relo_label_create_or_get(ctx, label_vmaddr);
  if (is_offset_undefined(offset)) { // pc relative target is beyond our scope
    label->link_to(PseudoLabel::kLabelImm19, relo_cur_src_vmaddr(ctx), (addr_t)ctx->buffer_cursor - ctx->mapped_addr);
    return 0;
  } else if (is_offset_uninitialized(offset)) { // pc relative target is in our control, but not handle yet
    label->link_to(PseudoLabel::kLabelImm19, relo_cur_src_vmaddr(ctx), (addr_t)ctx->buffer_cursor - ctx->mapped_addr);
    return 0;
  } else { // pc relative target is already handled
    off_t off = ctx->buffer_cursor + offset - ctx->buffer;
    off_t relocated_off = label->pos();
    int64_t new_offset = relo_dst_offset_to_vmaddr(ctx, relocated_off) - relo_src_offset_to_vmaddr(ctx, off);
    return new_offset;
  }
}
#endif

// ---

static inline bool inst_is_b_bl(uint32_t instr) {
  return (instr & UnconditionalBranchFixedMask) == UnconditionalBranchFixed;
}

static inline bool inst_is_ldr_literal(uint32_t instr) {
  return ((instr & LoadRegLiteralFixedMask) == LoadRegLiteralFixed);
}

static inline bool inst_is_adr(uint32_t instr) {
  return (instr & PCRelAddressingFixedMask) == PCRelAddressingFixed && (instr & PCRelAddressingMask) == ADR;
}

static inline bool inst_is_adrp(uint32_t instr) {
  return (instr & PCRelAddressingFixedMask) == PCRelAddressingFixed && (instr & PCRelAddressingMask) == ADRP;
}

static inline bool inst_is_b_cond(uint32_t instr) {
  return (instr & ConditionalBranchFixedMask) == ConditionalBranchFixed;
}

static inline bool inst_is_compare_b(uint32_t instr) {
  return (instr & CompareBranchFixedMask) == CompareBranchFixed;
}

static inline bool inst_is_test_b(uint32_t instr) {
  return (instr & TestBranchFixedMask) == TestBranchFixed;
}

struct relo_ctx_t {
  addr_t cursor;
  uint32_t relocated_insn_count;

  CodeMemBlock *origin;
  CodeMemBlock relocated{};
  CodeMemBuffer *relocated_buffer;

  explicit relo_ctx_t(MemBlock *origin) : origin(origin) {
    cursor = origin->addr();
  }

  uint32_t preferred_relo_size() {
    return origin->size;
  }

  void correct_final_relo_size() {
    origin->resize(relo_size());
  }

  uint32_t relo_size() {
    return (uintptr_t)cursor - origin->addr();
  }

  addr_t origin_start() {
    return origin->addr();
  }

  addr_t origin_cursor() {
    return origin->addr() + relo_size();
  }

  uint32_t origin_off() {
    return (uintptr_t)cursor - origin->addr();
  }

  addr_t relocated_start() {
    return relocated.addr();
  }

  addr_t relocated_cursor() {
    return relocated.addr() + relocated_buffer->size();
  }

  uint32_t relocated_off() {
    return relocated_buffer->size();
  }

  void record_relo_start() {
    DEBUG_LOG("relo: origin_off: %p, relocated_off: %p", origin_off(), relocated_off());
  }

  int relocate(bool branch);
};

#define DEFINE_DATA_LABEL(data, name) auto name##_data_label = _ createDataLabel(data);

int relo_ctx_t::relocate(bool branch) {
  TurboAssembler turbo_assembler_;
#undef _
#define _ turbo_assembler_. // NOLINT

  this->relocated_buffer = turbo_assembler_.code_buffer();

  while (relo_size() < preferred_relo_size()) {
    record_relo_start();

    uint32_t inst = *(uint32_t *)origin_cursor();
    if (inst_is_b_bl(inst)) {
      DEBUG_LOG("%d:relo <b_bl> at %p", relocated_insn_count++, origin_cursor());

      int64_t offset = decode_imm26_offset(inst);
      addr_t dst = origin_cursor() + offset;
      DEFINE_DATA_LABEL(dst, dst);
      {
        _ Ldr(TMP_REG_0, dst_data_label);
        if ((inst & UnconditionalBranchMask) == BL) {
          _ blr(TMP_REG_0);
        } else {
          _ br(TMP_REG_0);
        }
      }

    } else if (inst_is_ldr_literal(inst)) {
      DEBUG_LOG("%d:relo <ldr_literal> at %p", relocated_insn_count++, origin_cursor());

      int64_t offset = decode_imm19_offset(inst);
      addr_t dst = origin_cursor() + offset;

      int rt = decode_rt(inst);
      char opc = bits(inst, 30, 31);

      {
        _ Mov(TMP_REG_0, dst);
        if (opc == 0b00)
          _ ldr(W(rt), MemOperand(TMP_REG_0, 0));
        else if (opc == 0b01)
          _ ldr(X(rt), MemOperand(TMP_REG_0, 0));
        else {
          UNIMPLEMENTED();
        }
      }
    } else if (inst_is_adr(inst)) {
      DEBUG_LOG("%d:relo <adr> at %p", relocated_insn_count++, origin_cursor());

      int64_t offset = decode_immhi_immlo_offset(inst);
      addr_t dst = origin_cursor() + offset;

      int rd = decode_rd(inst);

      {
        _ Mov(X(rd), dst);
        ;
      }
    } else if (inst_is_adrp(inst)) {
      DEBUG_LOG("%d:relo <adrp> at %p", relocated_insn_count++, origin_cursor());

      int64_t offset = decode_immhi_immlo_zero12_offset(inst);
      addr_t dst = origin_cursor() + offset;
      dst = arm64_trunc_page(dst);

      int rd = decode_rd(inst);

      {
        _ Mov(X(rd), dst);
        ;
      }
    } else if (inst_is_b_cond(inst)) {
      DEBUG_LOG("%d:relo <b_cond> at %p", relocated_insn_count++, origin_cursor());

      int64_t offset = decode_imm19_offset(inst);
      addr_t dst = origin_cursor() + offset;

      uint32_t branch_inst = inst;
      {
        char cond = bits(inst, 0, 3);
        cond = cond ^ 1;
        set_bits(branch_inst, 0, 3, cond);

        int64_t offset = 4 * 3;
        uint32_t imm19 = offset >> 2;
        set_bits(branch_inst, 5, 23, imm19);
      }

      DEFINE_DATA_LABEL(dst, dst);

      {
        _ Emit(branch_inst);
        {
          _ Ldr(TMP_REG_0, dst_data_label);
          _ br(TMP_REG_0);
        }
      }
    } else if (inst_is_compare_b(inst)) {
      DEBUG_LOG("%d:relo <compare_b> at %p", relocated_insn_count++, origin_cursor());

      int64_t offset = decode_imm19_offset(inst);
      addr_t dst = origin_cursor() + offset;

      uint32_t branch_inst = inst;
      {
        char op = bit(inst, 24);
        op = op ^ 1;
        set_bit(branch_inst, 24, op);

        int64_t offset = 4 * 3;
        uint32_t imm19 = offset >> 2;
        set_bits(branch_inst, 5, 23, imm19);
      }

      DEFINE_DATA_LABEL(dst, dst);

      {
        _ Emit(branch_inst);
        {
          _ Ldr(TMP_REG_0, dst_data_label);
          _ br(TMP_REG_0);
        }
      }
    } else if (inst_is_test_b(inst)) {
      DEBUG_LOG("%d:relo <test_b> at %p", relocated_insn_count++, origin_cursor());

      int64_t offset = decode_imm14_offset(inst);
      addr_t dst = origin_cursor() + offset;

      uint32_t branch_inst = inst;
      {
        char op = bit(inst, 24);
        op = op ^ 1;
        set_bit(branch_inst, 24, op);

        int64_t offset = 4 * 3;
        uint32_t imm14 = offset >> 2;
        set_bits(branch_inst, 5, 18, imm14);
      }

      DEFINE_DATA_LABEL(dst, dst);

      {
        _ Emit(branch_inst);
        {
          _ Ldr(TMP_REG_0, dst_data_label);
          _ br(TMP_REG_0);
        }
      }
    } else {
      _ Emit(inst);
    }

    this->cursor += sizeof(uint32_t);
  }

  correct_final_relo_size();

  // TODO: if last instr is unlink branch, ignore it
  if (branch) {
    CodeGen codegen(&turbo_assembler_);
    codegen.LiteralLdrBranch(origin_cursor());
  }

  turbo_assembler_.relocDataLabels();

  relocated = AssemblerCodeBuilder::FinalizeFromTurboAssembler(&turbo_assembler_);
  return 0;
}

void GenRelocateCode(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch) {
  relo_ctx_t ctx(origin);
  ctx.relocate(branch);
  *relocated = ctx.relocated;
}

void GenRelocateCodeAndBranch(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated) {
  GenRelocateCode(buffer, origin, relocated, true);
}

#endif
