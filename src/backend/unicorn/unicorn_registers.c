#include "unicorn_registers.h"

uint16_t get_reg16(uc_engine *uc, int reg) {
  uint16_t value;
  uc_reg_read(uc, reg, &value);
  return value;
}

uint32_t get_reg32(uc_engine *uc, int reg) {
  uint32_t value;
  uc_reg_read(uc, reg, &value);
  return value;
}

void set_reg16(uc_engine *uc, int reg, uint16_t value) {
  /* Unicorn's register API treats a write through AX/BX/etc. as a complete
   * register value. In a 32-bit client, AX/BX/etc. must retain the high
   * half of the corresponding register. */
  int parent = 0;
  switch (reg) {
  case UC_X86_REG_AX:
    parent = UC_X86_REG_EAX;
    break;
  case UC_X86_REG_BX:
    parent = UC_X86_REG_EBX;
    break;
  case UC_X86_REG_CX:
    parent = UC_X86_REG_ECX;
    break;
  case UC_X86_REG_DX:
    parent = UC_X86_REG_EDX;
    break;
  case UC_X86_REG_SI:
    parent = UC_X86_REG_ESI;
    break;
  case UC_X86_REG_DI:
    parent = UC_X86_REG_EDI;
    break;
  case UC_X86_REG_BP:
    parent = UC_X86_REG_EBP;
    break;
  case UC_X86_REG_SP:
    parent = UC_X86_REG_ESP;
    break;
  default:
    break;
  }
  if (parent != 0) {
    uint32_t full = 0;
    uc_reg_read(uc, parent, &full);
    full = (full & 0xffff0000u) | value;
    uc_reg_write(uc, parent, &full);
    return;
  }
  uc_reg_write(uc, reg, &value);
}

void set_reg32(uc_engine *uc, int reg, uint32_t value) {
  uc_reg_write(uc, reg, &value);
}

void set_carry(uc_engine *uc, int set) {
  uint32_t flags;
  uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags);
  flags = set ? flags | 1u : flags & ~1u;
  uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags);
}

void set_zero(uc_engine *uc, int set) {
  uint32_t flags;
  uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags);
  flags = set ? flags | (1u << 6) : flags & ~(1u << 6);
  uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags);
}
