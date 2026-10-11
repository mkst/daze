#ifndef DAZE_DPMI_ALTERNATE_STATE_H
#define DAZE_DPMI_ALTERNATE_STATE_H

#include <stdint.h>

/* Guest-visible wire state contains no CPU-engine state. */
typedef struct {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, eflags;
  uint16_t cs, ds, es, fs, gs, ss;
  uint8_t reserved[8];
} DpmiAlternateState;

#define DAZE_DPMI_ALTERNATE_STATE_SIZE 60u

_Static_assert(sizeof(DpmiAlternateState) == DAZE_DPMI_ALTERNATE_STATE_SIZE,
               "DPMI alternate-state record must remain 60 bytes");

/* Requires EIP/ESP within 16 bits, nonzero CS/DS/SS, and reserved bytes zero.
 * Adapters separately validate guest addresses and selector bases. */
int daze_dpmi_alternate_state_valid(const DpmiAlternateState *state);

/* The 60-byte little-endian wire layout is independent of native struct padding. pack
 * does not validate; unpack checks the reserved bytes and 16-bit endpoint constraints. */
int daze_dpmi_alternate_state_pack(const DpmiAlternateState *state,
                                   uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE]);
int daze_dpmi_alternate_state_unpack(const uint8_t image[DAZE_DPMI_ALTERNATE_STATE_SIZE],
                                     DpmiAlternateState *state);

#endif
