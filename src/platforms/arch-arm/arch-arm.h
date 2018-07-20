
#define xASM(x) __asm(x)

#if 0
#undef get_current_fp_reg
#define get_current_fp_reg(fp_reg) xASM("mov %[fp_reg], fp" : [fp_reg] "=r"(fp_reg) :);
#endif