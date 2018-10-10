
#define xASM(x) __asm(x)

#if 0
#undef get_current_fp_reg
#define get_current_fp_reg(fp_reg) xASM("mov %[fp_reg], fp" : [fp_reg] "=r"(fp_reg) :);
#endif

/* borrow from gdb, refer: binutils-gdb/gdb/arch/arm.h */
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj, st, fn) (((obj) >> (st)) & submask((fn) - (st)))
#define bit(obj, st) (((obj) >> (st)) & 1)
#define sbits(obj, st, fn) ((long)(bits(obj, st, fn) | ((long)bit(obj, fn) * ~submask(fn - st))))