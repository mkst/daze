#include "unicorn_registers.h"

#include <inttypes.h>
#include <stdio.h>

int main(void) {
  uc_engine *uc = NULL;
  uc_err error = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
  if (error != UC_ERR_OK) {
    fprintf(stderr, "uc_open failed: %s\n", uc_strerror(error));
    return 1;
  }

  const uint32_t initial = 0x12340000;
  uint32_t result = 0;
  error = uc_reg_write(uc, UC_X86_REG_EBX, &initial);
  if (error == UC_ERR_OK) {
    set_reg16(uc, UC_X86_REG_BX, 0xbeef);
    error = uc_reg_read(uc, UC_X86_REG_EBX, &result);
  }
  int pass = error == UC_ERR_OK && result == 0x1234beef;
  if (!pass)
    fprintf(stderr, "16-bit register write: %s; expected EBX=1234beef, got %08" PRIx32 "\n",
            uc_strerror(error), result);
  const int low[] = {UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
                     UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP, UC_X86_REG_SP};
  const int full[] = {UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                      UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP};
  for (size_t i = 0; i < sizeof(low) / sizeof(low[0]); ++i) {
    const uint32_t seeded = 0xa5a50000 | (uint32_t)i;
    set_reg32(uc, full[i], seeded);
    set_reg16(uc, low[i], 0xbeef);
    pass &= get_reg16(uc, low[i]) == 0xbeef && get_reg32(uc, full[i]) == 0xa5a5beef;
  }
  set_reg16(uc, UC_X86_REG_DS, 0x1234);
  pass &= get_reg16(uc, UC_X86_REG_DS) == 0x1234;
  set_reg32(uc, UC_X86_REG_EFLAGS, 0x246);
  set_carry(uc, 1);
  pass &= get_reg32(uc, UC_X86_REG_EFLAGS) == 0x247;
  set_zero(uc, 0);
  pass &= get_reg32(uc, UC_X86_REG_EFLAGS) == 0x207;
  set_carry(uc, 0);
  pass &= get_reg32(uc, UC_X86_REG_EFLAGS) == 0x206;
  set_zero(uc, 1);
  pass &= get_reg32(uc, UC_X86_REG_EFLAGS) == 0x246;
  if (!pass) fprintf(stderr, "register/flag preservation contract failed\n");
  uc_close(uc);
  return pass ? 0 : 1;
}
