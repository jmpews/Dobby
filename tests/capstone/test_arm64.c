/* test1.c */

#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

// #define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
//

// releative call
// call 0xf
// #define CODE "\x2e\x74\x62"

// 0x58000050
#define CODE "\x50\x00\x00\x58"

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
	return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0, 1, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
	     printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
	             insn[j].op_str);
         //printf("0x%x\n", X86_REL_ADDR(insn[j]));
	 	}

	cs_free(insn, count);
	} else
	printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

	return 0;
}
