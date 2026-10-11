#ifndef DAZE_UNICORN_REGISTERS_H
#define DAZE_UNICORN_REGISTERS_H

#include <stdint.h>

#include "unicorn_context.h"

uint16_t get_reg16(uc_engine *uc, int reg);
uint32_t get_reg32(uc_engine *uc, int reg);
void set_reg16(uc_engine *uc, int reg, uint16_t value);
void set_reg32(uc_engine *uc, int reg, uint32_t value);
void set_carry(uc_engine *uc, int set);
void set_zero(uc_engine *uc, int set);
void skip_interrupt_instruction(uc_engine *uc, DazeUnicornRunState *run);
void daze_protected_dos_continuation_clear(DazeUnicornRunState *run);

#endif
