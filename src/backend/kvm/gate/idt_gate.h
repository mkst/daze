#ifndef DAZE_KVM_IDT_GATE_H
#define DAZE_KVM_IDT_GATE_H

#include "selector.h"

#include <stdint.h>
#include <stdlib.h>

/* The caller supplies placement and gate type for this architectural interrupt-gate
 * record. */
static inline void daze_kvm_encode_idt_gate(uint8_t entry[8], uint32_t offset, uint16_t selector,
                                            uint8_t type) {
  if (getenv("DAZE_KVM_GATE_DPL3") != NULL) type = (uint8_t)(type | 0x60u);
  entry[0] = (uint8_t)offset;
  entry[1] = (uint8_t)(offset >> 8);
  entry[2] = (uint8_t)selector;
  entry[3] = (uint8_t)(selector >> 8);
  entry[4] = 0;
  entry[5] = type;
  entry[6] = (uint8_t)(offset >> 16);
  entry[7] = (uint8_t)(offset >> 24);
}

#endif
